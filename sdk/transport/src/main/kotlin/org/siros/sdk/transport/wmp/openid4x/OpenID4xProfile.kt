// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp.openid4x

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.transport.StringOrStringListSerializer
import org.siros.sdk.transport.engine.CredentialRef
import org.siros.sdk.transport.wmp.*
import timber.log.Timber

// ---------------------------------------------------------------------------
// Flow Type Constants
// ---------------------------------------------------------------------------

object OID4FlowTypes {
    const val OID4VCI = "oid4vci"
    const val OID4VP = "oid4vp"

    /**
     * The sub-flows the ENGINE starts on the wallet (go-wmp `FlowTypeSign`, and the engine's literal `"match"`):
     * the wallet answers each with `wmp.flow.complete` / `wmp.flow.error` on the sub-flow's own id.
     */
    const val SIGN = "sign"
    const val MATCH = "match"
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
    const val EVALUATING_VERIFIER_TRUST = "evaluating_verifier_trust"
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

    /**
     * Report the outcome of the wallet's own DCQL matching
     * (go-wallet-backend#336, `ActionCredentialsMatched`). An empty match set
     * ends the presentation at once with `NO_MATCHING_CREDENTIAL` instead of
     * leaving it to the engine's five-minute user-interaction timeout; a
     * non-empty one is informational.
     */
    const val CREDENTIALS_MATCHED = "credentials_matched"
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
    /** Empty when [FlowCompleteResult.credentialResponseEncrypted]: the engine never held it, the wallet fills it in. */
    val credential: String = "",
    val vct: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
) {
    // The credential itself is never printed.
    override fun toString() = "CredentialResult(format=$format, credential=<redacted>, notificationId=$notificationId)"
}

/**
 * The typed view of a `wmp.flow.complete` `result`, which is the whole
 * engine `FlowCompleteMessage` object. [FlowCompleteParams.result] arrives as
 * a raw [JsonObject]; [decode] is the one place it is read into typed
 * [CredentialResult]s.
 */
@Serializable
data class FlowCompleteResult(
    val credentials: List<CredentialResult>? = null,
    @SerialName("credential_issuer") val credentialIssuer: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    /** See [org.siros.sdk.transport.engine.FlowCompleteMessage.credentialResponseEncrypted]. */
    @SerialName("credential_response_encrypted")
    @Serializable(with = org.siros.sdk.transport.EncryptedResponseFlagSerializer::class)
    val credentialResponseEncrypted: Boolean = false,
    /** See [org.siros.sdk.transport.engine.FlowCompleteMessage.credentialMetadata]: display-only members of a plain response. */
    @SerialName("credential_metadata")
    @Serializable(with = org.siros.sdk.transport.DisplayOnlyCredentialMetadataSerializer::class)
    val credentialMetadata: org.siros.sdk.transport.ResponseCredentialMetadata? = null,
    /** `redacted_members`: what a replayed completion withheld (the renewal material); see [org.siros.sdk.transport.engine.FlowCompleteMessage.redactedMembers]. */
    @SerialName("redacted_members")
    @Serializable(with = org.siros.sdk.transport.RedactedMembersSerializer::class)
    val redactedMembers: Set<String> = emptySet(),
) {
    init {
        // Only an encrypted completion has placeholders; a plain one carries a value for every credential.
        require(credentialResponseEncrypted || credentials.orEmpty().all { it.credential.isNotEmpty() }) {
            "A completion that is not encrypted carries a value for every credential"
        }
    }

    /** Whether the renewal material (`refresh_token`, `dpop_jwk`, `dpop_key_id`) was withheld, wholly or in part. */
    val renewalMaterialRedacted: Boolean
        get() = redactedMembers.any { it == "refresh_token" || it == "dpop_jwk" || it == "dpop_key_id" }

    companion object {
        private val lenient = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

        /** Decode [result]; null when absent. Throws on a malformed member (fail closed). */
        fun decode(result: JsonObject?): FlowCompleteResult? =
            result?.let { lenient.decodeFromJsonElement(serializer(), it) }
    }
}

@Serializable
data class VPTokenResult(
    @SerialName("vp_token") val vpToken: String? = null,
    @SerialName("presentation_submission") val presentationSubmission: JsonElement? = null,
    @SerialName("response_code") val responseCode: String? = null,
)

/**
 * One OID4VP `transaction_data` entry as an orchestrator relays it (OpenID4x
 * profile Section 3.2.5; go-wmp `openid4x.TransactionData`). The same shape
 * is used by the legacy engine WebSocket's `sign_request.params`.
 *
 * **[raw] is the only trustworthy member.** It is the base64url string the
 * verifier sent, and the only input to `transaction_data_hashes`
 * (OpenID4VP 1.0 Appendix B). [type], [payload] and [credentialIds] are the
 * orchestrator's decoded hint: a wallet decodes [raw] itself and must refuse
 * when the two disagree, never display or bind the hint.
 *
 * @property raw The entry exactly as the verifier sent it. `null` from an
 *   orchestrator that predates it; a wallet cannot bind to such an entry.
 * @property payload The entry's `payload` object (EC TS12 4.2), hint only.
 * @property params Pre-TS12 type-specific members (deprecated upstream).
 * @property hashAlgorithm Non-standard legacy member (deprecated upstream).
 * @property transactionDataHashesAlg The verifier's list of acceptable hash
 *   algorithms. An array in OpenID4VP; a bare string from older peers is
 *   accepted and read as a one-element list.
 */
@Serializable
data class TransactionData(
    val type: String,
    val params: JsonObject? = null,
    @SerialName("credential_ids") val credentialIds: List<String>? = null,
    @SerialName("hash_alg") val hashAlgorithm: String? = null,
    val raw: String? = null,
    val payload: JsonElement? = null,
    @SerialName("transaction_data_hashes_alg")
    @Serializable(with = StringOrStringListSerializer::class)
    val transactionDataHashesAlg: List<String>? = null,
)

@Serializable
data class SignSubFlowParams(
    val action: String,
    // Non-null for the generate_proof / sign_presentation callers that always
    // have them, but a DPoP-only `sign_client_auth` (credential, deferred,
    // notification request) carries no audience and no c_nonce, and a peer
    // may omit the members rather than send "". Default to empty so decoding
    // does not fail the whole sub-flow with INVALID_PARAMS.
    val nonce: String = "",
    val audience: String = "",
    @SerialName("proof_type") val proofType: String? = null,
    @SerialName("proof_types_supported") val proofTypesSupported: JsonObject? = null,
    @SerialName("parent_flow_id") val parentFlowId: String? = null,
    val count: Int? = null,
    @SerialName("transaction_data") val transactionData: List<TransactionData>? = null,
    /**
     * The OID4VP `response_mode` of the request being answered; required in
     * the key binding JWT of an SCA presentation (EC TS12 3.6). Present for
     * a request that carries `transaction_data`.
     */
    @SerialName("response_mode") val responseMode: String? = null,
    /** The credentials the orchestrator already selected for a `sign_presentation`, with their DCQL query ids. */
    @SerialName("credentials_to_include") val credentialsToInclude: List<CredentialRef>? = null,
    /** The verifier's own session id for this presentation. */
    @SerialName("verifier_session_id") val verifierSessionId: String? = null,
    /** PoP/proof `iss` (the flow's OAuth client_id) for `request_attestation` and `sign_client_auth`. */
    val issuer: String? = null,
    /**
     * `sign_client_auth` parameters (go-wallet-backend#317), same names and
     * meaning as the legacy transport's `SignRequestParams`: [htm]/[htu] ask
     * for a DPoP proof (with [dpopNonce] and [ath] claims), [keyId] names the
     * key to sign with on a renewal. `audience` doubles as the attestation
     * PoP aud when the request also needs client attestation.
     */
    val htm: String? = null,
    val htu: String? = null,
    @SerialName("dpop_nonce") val dpopNonce: String? = null,
    val ath: String? = null,
    @SerialName("key_id") val keyId: String? = null,
    /**
     * Holder commitments the issuer asked for (`["psc"]`), with the
     * [credentialType] and the exact [credentialIssuer] identifier string
     * (issuer metadata `credential_issuer`, verbatim) the wallet derives them
     * for. The wallet puts the claim `org.siros.psc` into the `jwt` proof.
     */
    @SerialName("holder_commitments") val holderCommitments: List<String>? = null,
    @SerialName("credential_type") val credentialType: String? = null,
    @SerialName("credential_issuer") val credentialIssuer: String? = null,
    /** Same members, same meaning as the legacy transport's [org.siros.sdk.transport.engine.SignRequestParams]. */
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: org.siros.sdk.transport.CredentialResponseEncryptionRequest? = null,
    val jwe: String? = null,
    val deferred: Boolean? = null,
    @SerialName("response_encryption") val responseEncryption: org.siros.sdk.transport.ResponseEncryptionRequest? = null,
    val state: String? = null,
    /** See [org.siros.sdk.transport.engine.SignRequestParams.verifiedRequest]. */
    @SerialName("verified_request") val verifiedRequest: org.siros.sdk.transport.VerifiedRequest? = null,
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
    // Appended last: a data class's property order is part of its binary API.
    /** Called with the flow id when the orchestrator cancels a flow (`wmp.flow.cancel`). */
    val onCancel: (suspend (String) -> Unit)? = null,
)

/** Result of a sign sub-flow request. */
data class SignSubFlowResult(
    val proofs: List<ProofObject>? = null,
    val vpToken: String? = null,
    /**
     * Extra members for the OID4VCI credential request the backend is about
     * to send on this wallet's behalf.
     *
     * Same field, same meaning and same reserved-name rule as the legacy
     * protocol's `SignResponseMessage.credential_request_extras`. The two
     * transports carry it identically on the wire so a backend can accept
     * either without a second code path, and so a flow behaves the same
     * whichever transport it runs over.
     */
    val credentialRequestExtras: JsonObject? = null,
    /**
     * `request_attestation` / `sign_client_auth` results, carried on the
     * wire under the same names as the legacy transport's
     * `SignResponseMessage` (`client_attestation`, `client_attestation_pop`,
     * `dpop_key_id`, `dpop_proof`) so a backend accepts either transport
     * without a second code path.
     */
    val clientAttestation: String? = null,
    val clientAttestationPoP: String? = null,
    val dpopKeyId: String? = null,
    val dpopProof: String? = null,
    /**
     * The engine-blind encryption answers, under the legacy transport's names (see
     * [org.siros.sdk.transport.engine.SignResponseMessage]): the public JWK of the key generated for the credential
     * response, the control fields of a decrypted response, the encrypted authorization response, and an error.
     */
    val credentialResponseEncryptionJwk: JsonObject? = null,
    val transactionId: String? = null,
    val interval: Int? = null,
    val responseJwe: String? = null,
    val error: String? = null,
    /** `decrypt_credential_response` for ISSUED credentials: how many the decrypted response carries (1..256). */
    val credentialCount: Int? = null,
) {
    init {
        require(responseJwe == null || vpToken == null) { "A sign result carries response_jwe or vp_token, never both" }
        require(listOfNotNull(credentialCount, transactionId, error).size <= 1) {
            "A decrypt_credential_response answer carries exactly one of credential_count, transaction_id or error"
        }
        // A refusal on this transport is a flow error, never a result; an error here carries no response either.
        require(responseJwe == null || error == null) { "A sign result that carries an error carries no response_jwe" }
    }
}

@Serializable
data class ProofObject(
    @SerialName("proof_type") val proofType: String = ProofType.JWT,
    val jwt: String? = null,
    val attestation: String? = null,
)

/** Result of a credential matching request. */
data class MatchResult(
    val matches: List<CredentialMatch>,
    /**
     * Why [matches] is empty - the wallet's own account, which the engine
     * relays in the `NO_MATCHING_CREDENTIAL` error it reports back. Null
     * whenever something matched.
     */
    val noMatchReason: String? = null,
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

// WMP error codes a sub-flow answer uses (go-wmp `ErrCapabilityNotSupported`, `ErrFlowError`).
private const val WMP_ERR_CAPABILITY_NOT_SUPPORTED = "-31005"
private const val WMP_ERR_FLOW_ERROR = "-31006"

/** The member the engine sets on a trust progress that wants an answer (its informational progress lacks it). */
private const val TRUST_EVALUATION_REQUIRED = "trust_evaluation_required"

/**
 * The wallet refuses a sign request on purpose (a sign-stage refusal, go-wallet-backend#472): thrown from the sign
 * callback, it is answered as a `wmp.flow.error` on the sign sub-flow with `data.reason = "rejected"`, which the
 * engine turns into an `access_denied` to the verifier, rather than as a plain sign failure. The message is
 * wallet-local (logged, never sent).
 */
class SignRefusedException(message: String) : Exception(message)

/**
 * OpenID4x WMP profile for OID4VCI and OID4VP flows.
 *
 * The engine drives the flow. It asks the wallet for signatures and credential matching by starting a **sub-flow**
 * (`wmp.flow.start` with flow type `sign` or `match`, go-wallet-backend `wmphandler.go` `startChildFlow`), which the
 * wallet acknowledges at once and answers later with `wmp.flow.complete` whose `result` is the response, or with
 * `wmp.flow.error`, on the SUB-FLOW's id. The engine matches the answer by that id, so the wallet echoes no
 * message id. Trust evaluation is a progress on the parent flow answered with a `trust_result` `wmp.flow.action`.
 */
class OpenID4xProfile(
    private val config: OpenID4xConfig = OpenID4xConfig(),
) : WmpProfile, WmpFlowHandler, AutoCloseable {

    private var peer: WmpPeerContext? = null

    /** Where sub-flow answers run, off the dispatch loop so the acknowledgement is never held up by a user prompt. */
    @Volatile
    internal var subFlowScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** Stops the sub-flow answers still running; [WmpPeer.close] calls it. */
    override fun close() {
        subFlowScope.cancel()
    }

    // ---- WmpProfile ----

    override val name: String = "openid4x"
    override val capabilities: List<String> = listOf("oid4vci", "oid4vp")

    override fun init(ctx: WmpPeerContext) {
        peer = ctx
    }

    // ---- WmpFlowHandler ----

    override val flowTypes: List<String> =
        listOf(OID4FlowTypes.OID4VCI, OID4FlowTypes.OID4VP, OID4FlowTypes.SIGN, OID4FlowTypes.MATCH)

    override suspend fun startFlow(params: FlowStartParams): FlowStartResult {
        // The engine waits for this acknowledgement (30 s), not for the answer: start the work and return.
        when (params.flowType) {
            OID4FlowTypes.SIGN -> subFlowScope.launch { answerSignSubFlow(params) }
            OID4FlowTypes.MATCH -> subFlowScope.launch { answerMatchSubFlow(params) }
        }
        return FlowStartResult(flowId = params.flowId, flowType = params.flowType)
    }

    override suspend fun handleProgress(params: FlowProgressParams) {
        val flowId = params.flowId
        val step = params.step
        val payload = params.payload

        Timber.d("OpenID4x progress: flow=$flowId step=$step")

        val wantsTrustAnswer = (payload?.get(TRUST_EVALUATION_REQUIRED) as? JsonPrimitive)?.booleanOrNull == true
        when {
            // Trust evaluation: the engine marks the progress that wants an answer. Issuer trust is the
            // `evaluating_trust` step, verifier trust `evaluating_verifier_trust`; both also send informational
            // progress under the same step, which must not be answered.
            wantsTrustAnswer && (step == VCIStep.EVALUATING_TRUST || step == VPStep.EVALUATING_VERIFIER_TRUST) -> {
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
        config.onCancel?.invoke(params.flowId)
    }

    // ---- Sub-flow answers ----

    private suspend fun answerSignSubFlow(start: FlowStartParams) {
        val ctx = peer ?: return
        val subFlowId = start.flowId
        val handler = config.onSignRequest
        if (handler == null) {
            sendSubFlowError(subFlowId, WMP_ERR_CAPABILITY_NOT_SUPPORTED, "sign requests are not supported", null)
            return
        }
        val signParams = start.params?.let {
            try {
                ctx.codec.json.decodeFromJsonElement(SignSubFlowParams.serializer(), it)
            } catch (e: Exception) {
                Timber.e("Failed to decode sign sub-flow params (${e.javaClass.simpleName})")
                null
            }
        }
        // The wallet keeps its per-flow state under the PARENT flow's id (the one it started), not the sub-flow's.
        val parentFlowId = signParams?.parentFlowId
        if (signParams == null || parentFlowId.isNullOrBlank()) {
            sendSubFlowError(subFlowId, WMP_ERR_FLOW_ERROR, "invalid sign request", null)
            return
        }

        try {
            sendSubFlowComplete(subFlowId, signResultJson(handler.invoke(parentFlowId, signParams)))
        } catch (e: CancellationException) {
            throw e
        } catch (e: TransactionDataError) {
            // A refused transaction_data request names its reason (the verifier-facing OpenID4VP error); the engine
            // reads capability-not-supported as "unsupported transaction data" and tells the verifier.
            Timber.w("Sign request refused: transaction_data (${e.reason.code})")
            sendSubFlowError(
                subFlowId, WMP_ERR_CAPABILITY_NOT_SUPPORTED, e.reason.code,
                buildJsonObject { put("verifier_error", JsonPrimitive(e.verifierError)) },
            )
        } catch (e: SignRefusedException) {
            Timber.w("Sign request refused by the wallet")
            sendSubFlowError(
                subFlowId, WMP_ERR_FLOW_ERROR, "sign request refused",
                buildJsonObject { put("reason", JsonPrimitive("rejected")) },
            )
        } catch (e: Exception) {
            // The reason stays local: the engine relays a flow error's message, and a sign failure's text can
            // name keys or credentials.
            Timber.e("Sign request handler failed (${e.javaClass.simpleName})")
            sendSubFlowError(subFlowId, WMP_ERR_FLOW_ERROR, "sign request failed", null)
        }
    }

    private suspend fun answerMatchSubFlow(start: FlowStartParams) {
        val subFlowId = start.flowId
        val handler = config.onMatchRequest
        if (handler == null) {
            sendSubFlowError(subFlowId, WMP_ERR_CAPABILITY_NOT_SUPPORTED, "match requests are not supported", null)
            return
        }
        val payload = start.params
        val parentFlowId = (payload?.get("parent_flow_id") as? JsonPrimitive)?.contentOrNull
        if (parentFlowId.isNullOrBlank()) {
            sendSubFlowError(subFlowId, WMP_ERR_FLOW_ERROR, "invalid match request", null)
            return
        }

        try {
            val result = handler.invoke(parentFlowId, payload)
            sendSubFlowComplete(subFlowId, matchResultJson(result))
            if (result.matches.isEmpty()) {
                // An empty answer also ends the presentation at once (credentials_matched, an action on the
                // PARENT flow) instead of leaving it to the engine's user-interaction timeout.
                sendCredentialsMatched(parentFlowId, result)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.e("Match request handler failed (${e.javaClass.simpleName})")
            sendSubFlowError(subFlowId, WMP_ERR_FLOW_ERROR, "match request failed", null)
        }
    }

    private suspend fun handleTrustEvaluation(flowId: String, payload: JsonObject?) {
        val handler = config.onTrustEvaluation ?: return

        try {
            val result = handler.invoke(flowId, payload)
            sendTrustResult(flowId, result)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.e("Trust evaluation handler failed (${e.javaClass.simpleName})")
            sendTrustResult(flowId, TrustResult(trusted = false, reason = e.message))
        }
    }

    // ---- Response helpers ----

    /**
     * The sign response as the engine reads it: `wmp.flow.complete`'s `result` is unmarshalled straight into its
     * `SignResponseMessage` (wmphandler.go `FlowComplete`), so the members carry that message's names and the
     * engine fills in the flow and message ids itself.
     */
    internal fun signResultJson(result: SignSubFlowResult): JsonObject {
        val ctx = peer ?: throw IllegalStateException("profile is not attached to a peer")
        return buildJsonObject {
            result.proofs?.let { proofs ->
                put("proofs", ctx.codec.json.encodeToJsonElement(ListSerializer(ProofObject.serializer()), proofs))
            }
            result.vpToken?.let { put("vp_token", JsonPrimitive(it)) }
            result.credentialRequestExtras?.let { put("credential_request_extras", it) }
            result.clientAttestation?.let { put("client_attestation", JsonPrimitive(it)) }
            result.clientAttestationPoP?.let { put("client_attestation_pop", JsonPrimitive(it)) }
            result.dpopKeyId?.let { put("dpop_key_id", JsonPrimitive(it)) }
            result.dpopProof?.let { put("dpop_proof", JsonPrimitive(it)) }
            result.credentialResponseEncryptionJwk?.let { put("credential_response_encryption_jwk", it) }
            result.transactionId?.let { put("transaction_id", JsonPrimitive(it)) }
            result.interval?.let { put("interval", JsonPrimitive(it)) }
            result.credentialCount?.let { put("credential_count", JsonPrimitive(it)) }
            result.responseJwe?.let { put("response_jwe", JsonPrimitive(it)) }
            result.error?.let { put("error", JsonPrimitive(it)) }
        }
    }

    /** The match response as the engine reads it (its `MatchResponseMessage`: `matches`, `no_match_reason`). */
    internal fun matchResultJson(result: MatchResult): JsonObject {
        val ctx = peer ?: throw IllegalStateException("profile is not attached to a peer")
        return buildJsonObject {
            put("matches", ctx.codec.json.encodeToJsonElement(ListSerializer(CredentialMatch.serializer()), result.matches))
            result.noMatchReason?.let { put("no_match_reason", JsonPrimitive(it)) }
        }
    }

    private suspend fun sendSubFlowComplete(subFlowId: String, result: JsonObject) {
        val ctx = peer ?: return
        ctx.notify(
            WmpMethods.FLOW_COMPLETE,
            ctx.codec.encodeParams(FlowCompleteParams(wmp = WmpMeta(), flowId = subFlowId, result = result)),
        )
    }

    private suspend fun sendSubFlowError(subFlowId: String, code: String, message: String, data: JsonObject?) {
        val ctx = peer ?: return
        ctx.notify(
            WmpMethods.FLOW_ERROR,
            ctx.codec.encodeParams(
                FlowErrorParams(wmp = WmpMeta(), flowId = subFlowId, code = code, message = message, data = data),
            ),
        )
    }

    /**
     * A generic flow action on the parent flow. The action's members go under `params`, where go-wmp's
     * `FlowActionParams` reads them (`wmphandler.go` takes the engine's payload from it); they were sent flat
     * next to `action`, so the engine saw an empty payload.
     */
    private suspend fun sendFlowAction(flowId: String, action: String, params: JsonObject) {
        val ctx = peer ?: return
        ctx.notify(
            WmpMethods.FLOW_ACTION,
            ctx.codec.encodeParams(FlowActionParams(wmp = WmpMeta(), flowId = flowId, action = action, params = params)),
        )
    }

    private suspend fun sendCredentialsMatched(flowId: String, result: MatchResult) {
        val ctx = peer ?: return
        sendFlowAction(
            flowId, OID4Action.CREDENTIALS_MATCHED,
            buildJsonObject {
                put("matches", ctx.codec.json.encodeToJsonElement(ListSerializer(CredentialMatch.serializer()), result.matches))
                result.noMatchReason?.let { put("no_match_reason", JsonPrimitive(it)) }
            },
        )
    }

    private suspend fun sendTrustResult(flowId: String, result: TrustResult) {
        sendFlowAction(
            flowId, "trust_result",
            buildJsonObject {
                put("trusted", JsonPrimitive(result.trusted))
                result.framework?.let { put("framework", JsonPrimitive(it)) }
                result.reason?.let { put("reason", JsonPrimitive(it)) }
            },
        )
    }
}
