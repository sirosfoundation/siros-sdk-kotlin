// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp.openid4x

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.transport.StringOrStringListSerializer
import org.siros.sdk.transport.engine.CredentialRef
import org.siros.sdk.transport.wmp.*
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap

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

/** The most sub-flows kept at once; past it the answered ones are forgotten (their replay is no longer possible). */
private const val MAX_SUB_FLOWS = 256

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

    /**
     * Where sub-flow answers run, off the dispatch loop so the acknowledgement is never held up by a user prompt. The
     * handler is the last boundary: nothing that escapes an answer task may reach the thread's uncaught-exception
     * handler (on Android, the app's crash).
     */
    @Volatile
    internal var subFlowScope: CoroutineScope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default +
            CoroutineExceptionHandler { _, e -> Timber.e("WMP sub-flow work failed (${e.javaClass.simpleName})") },
    )

    /** How many sub-flows are kept at once; a variable only so tests need not create 256 (see [MAX_SUB_FLOWS]). */
    @Volatile
    internal var maxSubFlows: Int = MAX_SUB_FLOWS

    /** Runs between a sub-flow's registration and the assignment of its job (tests only). */
    @Volatile
    internal var beforeJobAssigned: (() -> Unit)? = null

    /** What the wallet has decided to answer on a sub-flow: the frames to send, in order. */
    private class SubFlowAnswer(val frames: List<Pair<String, JsonObject>>)

    /**
     * One sub-flow the engine started, keyed by its own id. The engine re-sends a start under the SAME id when a resumed
     * session reissues it, so this is also how a repeat is told from a new request.
     */
    private class SubFlow(val childId: String, val parentId: String?, val lifetime: Job) {
        /** True once every frame of the answer has been sent: only then may the entry be forgotten to make room. */
        @Volatile var sent: Boolean = false

        /** Set the moment the answer is decided (before it is sent), so a failed send can be replayed, never recomputed. */
        @Volatile var answer: SubFlowAnswer? = null
    }

    private val subFlows = ConcurrentHashMap<String, SubFlow>()

    /** Stops the sub-flow answers still running and forgets them; [WmpPeer.close] calls it, also when closing the session failed. */
    override fun close() {
        val all = subFlows.values.toList()
        subFlows.clear()
        all.forEach { it.lifetime.cancel() }
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
            OID4FlowTypes.SIGN, OID4FlowTypes.MATCH -> beginSubFlow(params)
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
        stopSubFlows(params.flowId)
        config.onComplete?.invoke(params.flowId, params.result)
    }

    override suspend fun handleError(params: FlowErrorParams) {
        stopSubFlows(params.flowId)
        config.onError?.invoke(params.flowId, params.code, params.message)
    }

    override suspend fun handleCancel(params: FlowCancelParams) {
        Timber.d("OpenID4x flow cancelled: ${params.flowId} reason=${params.reason}")
        stopSubFlows(params.flowId)
        config.onCancel?.invoke(params.flowId)
    }

    // ---- Sub-flow answers ----

    /** A flow this peer has ended itself (a local cancel): the sub-flows of it stop before its state is released. */
    override fun flowEnded(flowId: String) = stopSubFlows(flowId)

    /**
     * Stops the sub-flows whose child or parent id is [flowId] and forgets them: a callback still waiting (a consent prompt, a
     * signature) is cancelled, and one that ignores cancellation and returns late finds its sub-flow gone and answers nothing.
     * Runs BEFORE the terminal callbacks that release the flow's state.
     */
    private fun stopSubFlows(flowId: String) {
        for (sub in subFlows.values.toList()) {
            if ((sub.childId == flowId || sub.parentId == flowId) && subFlows.remove(sub.childId, sub)) sub.lifetime.cancel()
        }
    }

    private fun beginSubFlow(start: FlowStartParams) {
        val existing = subFlows[start.flowId]
        if (existing != null) {
            // A repeat (a resumed session reissues the start under the same id): the first start is acknowledged and its work is
            // not run again. An answer already decided is sent again (the first send may have failed); one still pending is simply
            // left to finish. The replay shares the sub-flow's lifetime, so a stop cancels it with the original.
            existing.answer?.let { decided -> subFlowScope.launch(existing.lifetime) { emit(existing, decided) } }
            return
        }
        if (subFlows.size >= maxSubFlows) {
            // Room is made only from sub-flows whose answer has been completely sent; one that is pending, or whose frames are
            // still on their way, is never evicted. With nothing to evict the new start is refused.
            subFlows.values.filter { it.sent }.forEach { if (subFlows.remove(it.childId, it)) it.lifetime.cancel() }
            if (subFlows.size >= maxSubFlows) {
                refuseSubFlow(start)
                return
            }
        }
        val parentId = (start.params?.get("parent_flow_id") as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }
        val sub = SubFlow(start.flowId, parentId, SupervisorJob(subFlowScope.coroutineContext[Job]))
        if (subFlows.putIfAbsent(start.flowId, sub) != null) {
            sub.lifetime.cancel()
            return
        }
        // Test seam: a stop that lands between the registration above and the job below.
        beforeJobAssigned?.invoke()
        val job = subFlowScope.launch(sub.lifetime, start = CoroutineStart.LAZY) { runSubFlow(sub, start) }
        // A stop in the gap found no job to cancel and removed the entry: this sub-flow is already over, and its callback (a
        // signature, a consent prompt) must not start. After this check a stop cancels the lifetime, and the job with it.
        if (subFlows[start.flowId] !== sub) {
            sub.lifetime.cancel()
            return
        }
        job.start()
    }

    /** The sub-flow table is full of live work: the request is answered with a generic error, nothing is evicted for it. */
    private fun refuseSubFlow(start: FlowStartParams) {
        val ctx = peer ?: return
        Timber.w("Too many pending WMP sub-flows; refusing one")
        subFlowScope.launch {
            try {
                ctx.notify(
                    WmpMethods.FLOW_ERROR,
                    ctx.codec.encodeParams(
                        FlowErrorParams(wmp = WmpMeta(), flowId = start.flowId, code = WMP_ERR_FLOW_ERROR, message = "too many pending requests"),
                    ),
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w("Could not refuse a WMP sub-flow (${e.javaClass.simpleName})")
            }
        }
    }

    /** The boundary around one whole answer task: nothing but cancellation leaves it. */
    private suspend fun runSubFlow(sub: SubFlow, start: FlowStartParams) {
        try {
            when (start.flowType) {
                OID4FlowTypes.SIGN -> answerSignSubFlow(sub, start)
                OID4FlowTypes.MATCH -> answerMatchSubFlow(sub, start)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Text stays out of the log: it can name keys or credentials.
            Timber.e("WMP sub-flow answer failed (${e.javaClass.simpleName})")
        }
    }

    /**
     * Records [frames] as the sub-flow's answer and sends them. Recorded first, so a send that fails is replayed by a repeated
     * start rather than lost.
     */
    private suspend fun answer(sub: SubFlow, frames: List<Pair<String, JsonObject>>) {
        val decided = SubFlowAnswer(frames)
        sub.answer = decided
        emit(sub, decided)
    }

    /**
     * Sends an answer's frames, unless the sub-flow has been stopped in the meantime (its flow ended or was cancelled, or the
     * profile closed): cancellation is cooperative, so a callback that was blocking when that happened still returns here.
     * A failed send is logged and dropped; it never reaches the app (the connection is down and the engine retries).
     */
    private suspend fun emit(sub: SubFlow, decided: SubFlowAnswer) {
        val ctx = peer ?: return
        for ((method, params) in decided.frames) {
            currentCoroutineContext().ensureActive()
            if (subFlows[sub.childId] !== sub) return
            try {
                // Checked again by the peer once it holds its send lock: this send may have queued behind another, and the
                // sub-flow can have been stopped while it waited.
                if (!ctx.notifyIf(method, params) { sub.lifetime.isActive && subFlows[sub.childId] === sub }) return
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w("Could not send a WMP sub-flow answer (${e.javaClass.simpleName})")
                return
            }
        }
        sub.sent = true
    }

    private suspend fun answerComplete(sub: SubFlow, result: JsonObject, followUps: List<Pair<String, JsonObject>> = emptyList()) {
        val ctx = peer ?: return
        answer(
            sub,
            listOf(
                WmpMethods.FLOW_COMPLETE to ctx.codec.encodeParams(
                    FlowCompleteParams(wmp = WmpMeta(), flowId = sub.childId, result = result),
                ),
            ) + followUps,
        )
    }

    private suspend fun answerError(sub: SubFlow, code: String, message: String, data: JsonObject?) {
        val ctx = peer ?: return
        answer(
            sub,
            listOf(
                WmpMethods.FLOW_ERROR to ctx.codec.encodeParams(
                    FlowErrorParams(wmp = WmpMeta(), flowId = sub.childId, code = code, message = message, data = data),
                ),
            ),
        )
    }

    /** A deliberate refusal: a flow error with `data.reason = "rejected"`, which the engine answers to the verifier as access_denied. */
    private suspend fun answerRefused(sub: SubFlow) =
        answerError(sub, WMP_ERR_FLOW_ERROR, "sign request refused", buildJsonObject { put("reason", JsonPrimitive("rejected")) })

    private suspend fun answerSignSubFlow(sub: SubFlow, start: FlowStartParams) {
        val ctx = peer ?: return
        val handler = config.onSignRequest
        if (handler == null) {
            answerError(sub, WMP_ERR_CAPABILITY_NOT_SUPPORTED, "sign requests are not supported", null)
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
            answerError(sub, WMP_ERR_FLOW_ERROR, "invalid sign request", null)
            return
        }

        try {
            answerComplete(sub, signResultJson(handler.invoke(parentFlowId, signParams)))
        } catch (e: CancellationException) {
            throw e
        } catch (e: TransactionDataError) {
            if (e.reason == TransactionDataReason.DECLINED) {
                // The user declined the transaction: a refusal like any other, not an unsupported request (the engine reads
                // capability-not-supported as "unsupported transaction data" and would tell the verifier that).
                Timber.w("Sign request declined by the user (transaction_data)")
                answerRefused(sub)
            } else {
                // A refused transaction_data request names its reason (the verifier-facing OpenID4VP error); the engine reads
                // capability-not-supported as "unsupported transaction data" and tells the verifier.
                Timber.w("Sign request refused: transaction_data (${e.reason.code})")
                answerError(
                    sub, WMP_ERR_CAPABILITY_NOT_SUPPORTED, e.reason.code,
                    buildJsonObject { put("verifier_error", JsonPrimitive(e.verifierError)) },
                )
            }
        } catch (e: SignRefusedException) {
            Timber.w("Sign request refused by the wallet")
            answerRefused(sub)
        } catch (e: Exception) {
            // The reason stays local: the engine relays a flow error's message, and a sign failure's text can
            // name keys or credentials.
            Timber.e("Sign request handler failed (${e.javaClass.simpleName})")
            answerError(sub, WMP_ERR_FLOW_ERROR, "sign request failed", null)
        }
    }

    private suspend fun answerMatchSubFlow(sub: SubFlow, start: FlowStartParams) {
        val handler = config.onMatchRequest
        if (handler == null) {
            answerError(sub, WMP_ERR_CAPABILITY_NOT_SUPPORTED, "match requests are not supported", null)
            return
        }
        val payload = start.params
        val parentFlowId = (payload?.get("parent_flow_id") as? JsonPrimitive)?.contentOrNull
        if (parentFlowId.isNullOrBlank()) {
            answerError(sub, WMP_ERR_FLOW_ERROR, "invalid match request", null)
            return
        }

        try {
            val result = handler.invoke(parentFlowId, payload)
            // An empty answer also ends the presentation at once (credentials_matched, an action on the PARENT flow) instead
            // of leaving it to the engine's user-interaction timeout. It travels with the completion, and is replayed with it.
            val followUps = if (result.matches.isEmpty()) listOf(credentialsMatchedFrame(parentFlowId, result)) else emptyList()
            answerComplete(sub, matchResultJson(result), followUps)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.e("Match request handler failed (${e.javaClass.simpleName})")
            answerError(sub, WMP_ERR_FLOW_ERROR, "match request failed", null)
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

    /** `credentials_matched`, an action on the PARENT flow, as the frame to send (members under `params`, see [sendFlowAction]). */
    private fun credentialsMatchedFrame(flowId: String, result: MatchResult): Pair<String, JsonObject> {
        val ctx = peer ?: throw IllegalStateException("profile is not attached to a peer")
        return WmpMethods.FLOW_ACTION to ctx.codec.encodeParams(
            FlowActionParams(
                wmp = WmpMeta(), flowId = flowId, action = OID4Action.CREDENTIALS_MATCHED,
                params = buildJsonObject {
                    put("matches", ctx.codec.json.encodeToJsonElement(ListSerializer(CredentialMatch.serializer()), result.matches))
                    result.noMatchReason?.let { put("no_match_reason", JsonPrimitive(it)) }
                },
            ),
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
