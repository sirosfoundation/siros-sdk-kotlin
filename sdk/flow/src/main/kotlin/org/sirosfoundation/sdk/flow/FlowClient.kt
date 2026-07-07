package org.sirosfoundation.sdk.flow

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.sirosfoundation.sdk.auth.BackendApiClient
import org.sirosfoundation.sdk.keystore.KeystoreManager
import org.sirosfoundation.sdk.transport.CredentialNotifier
import org.sirosfoundation.sdk.transport.wmp.WmpMeta
import org.sirosfoundation.sdk.transport.wmp.WmpSession
import timber.log.Timber
import java.util.UUID

/** Proof type precedence order (attestation preferred over jwt). */
private val PROOF_TYPE_PRECEDENCE = listOf("attestation", "jwt")

/**
 * Manages OID4VCI and OID4VP flows over a WMP session.
 *
 * Translates WMP flow notifications into [FlowEvent]s for the SDK consumer.
 * When autoSign is enabled, automatically handles sign_request events
 * using the provided [KeystoreManager]. When disabled, the consumer must
 * call [respondToSignRequest] manually.
 */
class FlowClient(
    private val session: WmpSession,
    private val keystore: KeystoreManager,
    private val apiClient: BackendApiClient? = null,
    private val autoSign: Boolean = true,
    private val json: Json = Json { ignoreUnknownKeys = true },
) : CredentialNotifier {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _events = Channel<FlowEvent>(Channel.BUFFERED)

    /** Flow events stream. SDK consumers observe this to drive UI. */
    fun events(): Flow<FlowEvent> = _events.receiveAsFlow()

    /** Start listening for flow notifications from the WMP session. */
    fun start() {
        scope.launch {
            session.notifications().collect { notification ->
                try {
                    handleNotification(notification)
                } catch (e: Exception) {
                    Timber.e(e, "Error handling flow notification: ${notification.method}")
                }
            }
        }
    }

    /** Start an OID4VCI credential issuance flow. */
    suspend fun startIssuance(params: OID4VCIFlowParams): String {
        val flowId = UUID.randomUUID().toString()
        val flowParams = buildJsonObject {
            put("flow_type", "issuance")
            put("flow_id", flowId)
            params.credentialOfferUri?.let { put("credential_offer_uri", it) }
            params.issuerUrl?.let { put("issuer_url", it) }
            put("wmp", json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
        }
        session.sendRequest("wmp.flow.start", flowParams)
        return flowId
    }

    /** Start an OID4VP verifiable presentation flow. */
    suspend fun startPresentation(params: OID4VPFlowParams): String {
        val flowId = UUID.randomUUID().toString()
        val flowParams = buildJsonObject {
            put("flow_type", "presentation")
            put("flow_id", flowId)
            params.requestUri?.let { put("request_uri", it) }
            put("wmp", json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
        }
        session.sendRequest("wmp.flow.start", flowParams)
        return flowId
    }

    /** Send a flow action (e.g., user consent, credential selection). */
    suspend fun sendAction(flowId: String, action: String, payload: JsonObject? = null) {
        val params = buildJsonObject {
            put("flow_id", flowId)
            put("action", action)
            payload?.let { put("params", it) }
            put("wmp", json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
        }
        session.sendRequest("wmp.flow.action", params)
    }

    /** Respond to a sign request (when autoSign is disabled). */
    suspend fun respondToSignRequest(flowId: String, messageId: String, response: SignResponse) {
        val params = buildJsonObject {
            put("flow_id", flowId)
            put("message_id", messageId)
            response.proofJwt?.let { put("proof_jwt", it) }
            response.vpToken?.let { put("vp_token", it) }
            response.attestation?.let { put("attestation", it) }
            response.proofType?.let { put("proof_type", it) }
            put("wmp", json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
        }
        session.sendNotification("wmp.flow.action", params)
    }

    /** Respond to a match request. */
    suspend fun respondToMatchRequest(flowId: String, messageId: String, response: MatchResponse) {
        val params = buildJsonObject {
            put("flow_id", flowId)
            put("message_id", messageId)
            put("credential_ids", kotlinx.serialization.json.JsonArray(
                response.credentialIds.map { kotlinx.serialization.json.JsonPrimitive(it) }
            ))
            put("wmp", json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
        }
        session.sendNotification("wmp.flow.action", params)
    }

    // ===== CredentialNotifier =====

    /**
     * Send an OID4VCI §10 credential lifecycle notification over WMP.
     * Fire-and-forget: errors are logged, never thrown.
     */
    override fun sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String?,
    ) {
        if (session.state.value != org.sirosfoundation.sdk.transport.wmp.WmpSessionState.ACTIVE) return
        scope.launch {
            try {
                val params = buildJsonObject {
                    put("wmp", json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
                    put("flow_id", flowId)
                    put("notification_id", notificationId)
                    put("event", event)
                    eventDescription?.let { put("event_description", it) }
                }
                session.sendNotification("wmp.credential.notification", params)
            } catch (e: Exception) {
                Timber.w(e, "Failed to send credential notification for flow $flowId")
            }
        }
    }

    private suspend fun handleNotification(notification: org.sirosfoundation.sdk.transport.wmp.JsonRpcRequest) {
        val params = notification.params ?: return
        val flowId = params["flow_id"]?.jsonPrimitive?.content ?: return

        when (notification.method) {
            "wmp.flow.progress" -> {
                val step = params["step"]?.jsonPrimitive?.content ?: ""
                val payload = params["payload"]?.jsonObject
                _events.send(FlowEvent.Progress(flowId, step, payload))

                // Handle sign requests embedded in progress
                if (step == "sign_request") {
                    handleSignRequest(flowId, params)
                }
                if (step == "match_request") {
                    handleMatchRequest(flowId, params)
                }
            }
            "wmp.flow.complete" -> {
                val result = params["result"]?.jsonObject
                _events.send(FlowEvent.Complete(flowId, result))
            }
            "wmp.flow.error" -> {
                val code = params["code"]?.jsonPrimitive?.content
                val message = params["message"]?.jsonPrimitive?.content
                _events.send(FlowEvent.Error(flowId, code, message))
            }
        }
    }

    private suspend fun handleSignRequest(flowId: String, params: JsonObject) {
        val messageId = params["message_id"]?.jsonPrimitive?.content ?: return
        val payload = params["payload"]?.jsonObject ?: return
        val actionStr = payload["action"]?.jsonPrimitive?.content ?: return
        val action = when (actionStr) {
            "generate_proof" -> SignAction.GENERATE_PROOF
            "sign_presentation" -> SignAction.SIGN_PRESENTATION
            else -> return
        }
        val signParams = json.decodeFromJsonElement(SignParams.serializer(), payload)

        if (autoSign) {
            try {
                val response = when (action) {
                    SignAction.GENERATE_PROOF -> {
                        // Select proof type: prefer attestation if supported and apiClient is available
                        val selectedType = selectProofType(signParams.proofTypesSupported)

                        if (selectedType == "attestation" && apiClient != null) {
                            val count = maxOf(signParams.count ?: 1, 1)
                            val keypairs = keystore.generateKeypairs(count)
                            val jwks = keypairs.map { it.publicKeyJWK }
                            val secProps = keystore.securityProperties()
                            val keyAttestation = apiClient.requestKeyAttestation(
                                jwks = jwks,
                                nonce = signParams.nonce ?: "",
                                securityProperties = secProps,
                            )
                            SignResponse(attestation = keyAttestation, proofType = "attestation")
                        } else {
                            val proof = keystore.generateProof(
                                audience = signParams.audience ?: "",
                                nonce = signParams.nonce ?: "",
                            )
                            SignResponse(proofJwt = proof, proofType = "jwt")
                        }
                    }
                    SignAction.SIGN_PRESENTATION -> {
                        val vp = keystore.signPresentation(
                            nonce = signParams.nonce ?: "",
                            audience = signParams.audience ?: "",
                            credentialIds = signParams.credentialsToInclude?.map {
                                it["credential_id"]?.jsonPrimitive?.content ?: ""
                            } ?: emptyList(),
                        )
                        SignResponse(vpToken = vp)
                    }
                }
                respondToSignRequest(flowId, messageId, response)
            } catch (e: Exception) {
                Timber.e(e, "Auto-sign failed for flow $flowId")
                _events.send(FlowEvent.SignRequest(flowId, messageId, action, signParams))
            }
        } else {
            _events.send(FlowEvent.SignRequest(flowId, messageId, action, signParams))
        }
    }

    /** Select the preferred proof type from supported types. */
    private fun selectProofType(proofTypesSupported: JsonObject?): String {
        if (proofTypesSupported == null) return "jwt"
        return PROOF_TYPE_PRECEDENCE.firstOrNull { proofTypesSupported.containsKey(it) } ?: "jwt"
    }

    private suspend fun handleMatchRequest(flowId: String, params: JsonObject) {
        val messageId = params["message_id"]?.jsonPrimitive?.content ?: return
        val dcqlQuery = params["payload"]?.jsonObject?.get("dcql_query")?.jsonObject ?: return
        _events.send(FlowEvent.MatchRequest(flowId, messageId, dcqlQuery))
    }
}
