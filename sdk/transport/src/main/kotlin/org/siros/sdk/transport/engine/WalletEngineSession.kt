// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.siros.sdk.transport.CredentialNotifier
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * WebSocket session client for the wallet backend engine protocol.
 *
 * This implements the wallet backend's custom type-based WebSocket protocol
 * (handshake → flow_start → sign_request/match_request → flow_complete).
 *
 * Connection sequence:
 * 1. Open WebSocket to `/api/v2/wallet?tenant_id=<tenantId>`
 * 2. Send `{"type":"handshake","app_token":"<jwt>"}`
 * 3. Receive `{"type":"handshake_complete","session_id":"...","capabilities":[...]}`
 * 4. Exchange flow messages until disconnect
 */
class WalletEngineSession(
    private val baseUrl: String,
    private val tenantId: String = "default",
    private val client: OkHttpClient = defaultClient(),
) : CredentialNotifier {
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, FAILED }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val _state = MutableStateFlow(State.DISCONNECTED)
    val state: StateFlow<State> = _state

    private var webSocket: WebSocket? = null
    private var sessionId: String? = null
    private var lastAppToken: String? = null
    private var reconnectAttempts = 0
    private val maxReconnectAttempts = 5
    private val baseReconnectDelayMs = 1000L

    private val incomingMessages = Channel<EngineMessage>(Channel.BUFFERED)
    private val flowProgressChannel = Channel<FlowProgressMessage>(Channel.BUFFERED)
    private val flowCompleteChannel = Channel<FlowCompleteMessage>(Channel.BUFFERED)
    private val flowErrorChannel = Channel<FlowErrorMessage>(Channel.BUFFERED)
    private val signRequestChannel = Channel<SignRequestMessage>(Channel.BUFFERED)
    private val matchRequestChannel = Channel<MatchRequestMessage>(Channel.BUFFERED)
    private val pushChannel = Channel<PushMessage>(Channel.BUFFERED)
    private val notificationAckChannel = Channel<NotificationAckMessage>(Channel.BUFFERED)

    /** All incoming messages as raw [EngineMessage] (for type-based dispatch). */
    fun messages(): Flow<EngineMessage> = incomingMessages.receiveAsFlow()

    /** Server flow progress updates. */
    fun flowProgress(): Flow<FlowProgressMessage> = flowProgressChannel.receiveAsFlow()

    /** Server flow completion events. */
    fun flowComplete(): Flow<FlowCompleteMessage> = flowCompleteChannel.receiveAsFlow()

    /** Server flow error events. */
    fun flowErrors(): Flow<FlowErrorMessage> = flowErrorChannel.receiveAsFlow()

    /** Server signing requests. */
    fun signRequests(): Flow<SignRequestMessage> = signRequestChannel.receiveAsFlow()

    /** Server credential matching requests. */
    fun matchRequests(): Flow<MatchRequestMessage> = matchRequestChannel.receiveAsFlow()

    /** Server push notifications. */
    fun pushMessages(): Flow<PushMessage> = pushChannel.receiveAsFlow()

    /**
     * Acknowledgements for OID4VCI §10 credential notifications sent via
     * [sendCredentialNotification]. Each value reports whether the backend
     * forwarded the notification to the issuer (`status == "forwarded"`) or
     * rejected it, including any `error` detail.
     */
    fun notificationAcks(): Flow<NotificationAckMessage> = notificationAckChannel.receiveAsFlow()

    /** Whether the underlying WebSocket is currently connected. */
    val isConnected: Boolean get() = webSocket != null

    /**
     * Connect to the engine WebSocket and perform the handshake.
     * @param appToken JWT obtained from login/register
     */
    fun connect(appToken: String) {
        if (_state.value == State.CONNECTED) return
        _state.value = State.CONNECTING
        lastAppToken = appToken
        reconnectAttempts = 0
        doConnect(appToken)
    }

    private fun doConnect(appToken: String) {
        val wsUrl = baseUrl
            .replace("https://", "wss://")
            .replace("http://", "ws://")
            .trimEnd('/') + "/api/v2/wallet?tenant_id=$tenantId"

        val request = Request.Builder()
            .url(wsUrl)
            .header("Sec-WebSocket-Protocol", "wmp.v1")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Timber.d("Engine WebSocket connected, sending handshake")
                reconnectAttempts = 0
                val handshake = json.encodeToString(
                    HandshakeMessage.serializer(),
                    HandshakeMessage(appToken = appToken),
                )
                ws.send(handshake)
            }

            override fun onMessage(ws: WebSocket, text: String) {
                scope.launch { handleMessage(text) }
            }

            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                Timber.d("Engine WebSocket closing: $code $reason")
                ws.close(1000, null)
                scheduleReconnect()
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                Timber.e(t, "Engine WebSocket failure")
                scheduleReconnect()
            }
        })
    }

    private fun scheduleReconnect() {
        val token = lastAppToken
        if (token == null || reconnectAttempts >= maxReconnectAttempts) {
            Timber.w("WebSocket reconnection exhausted ($reconnectAttempts attempts)")
            _state.value = State.FAILED
            return
        }
        _state.value = State.RECONNECTING
        reconnectAttempts++
        val delayMs = baseReconnectDelayMs * (1L shl (reconnectAttempts - 1).coerceAtMost(4))
        Timber.i("Reconnecting in ${delayMs}ms (attempt $reconnectAttempts/$maxReconnectAttempts)")
        scope.launch {
            kotlinx.coroutines.delay(delayMs)
            if (_state.value == State.RECONNECTING) {
                doConnect(token)
            }
        }
    }

    private suspend fun handleMessage(text: String) {
        try {
            val element = json.parseToJsonElement(text).jsonObject
            val type = element["type"]?.jsonPrimitive?.content ?: return

            when (type) {
                MessageTypes.HANDSHAKE_COMPLETE -> {
                    val msg = json.decodeFromString(HandshakeCompleteMessage.serializer(), text)
                    sessionId = msg.sessionId
                    _state.value = State.CONNECTED
                    Timber.i("Engine session established: ${msg.sessionId}")
                }
                MessageTypes.FLOW_PROGRESS -> {
                    val msg = json.decodeFromString(FlowProgressMessage.serializer(), text)
                    flowProgressChannel.trySend(msg)
                }
                MessageTypes.FLOW_COMPLETE -> {
                    val msg = json.decodeFromString(FlowCompleteMessage.serializer(), text)
                    flowCompleteChannel.trySend(msg)
                }
                MessageTypes.FLOW_ERROR -> {
                    val msg = json.decodeFromString(FlowErrorMessage.serializer(), text)
                    flowErrorChannel.trySend(msg)
                }
                MessageTypes.SIGN_REQUEST -> {
                    val msg = json.decodeFromString(SignRequestMessage.serializer(), text)
                    signRequestChannel.trySend(msg)
                }
                MessageTypes.MATCH_REQUEST -> {
                    val msg = json.decodeFromString(MatchRequestMessage.serializer(), text)
                    matchRequestChannel.trySend(msg)
                }
                MessageTypes.PUSH -> {
                    val msg = json.decodeFromString(PushMessage.serializer(), text)
                    pushChannel.trySend(msg)
                }
                MessageTypes.NOTIFICATION_ACK -> {
                    val msg = json.decodeFromString(NotificationAckMessage.serializer(), text)
                    notificationAckChannel.trySend(msg)
                }
                MessageTypes.ERROR -> {
                    val msg = json.decodeFromString(ErrorMessage.serializer(), text)
                    Timber.e("Engine error: ${msg.code} — ${msg.details}")
                    _state.value = State.FAILED
                }
                else -> Timber.w("Unknown engine message type: $type")
            }

            // Also send to the raw messages channel
            val envelope = json.decodeFromString(EngineMessage.serializer(), text)
            incomingMessages.trySend(envelope)
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse engine message")
        }
    }

    // ── Client → Server messages ────────────────────────────────────

    /** Start an OID4VCI credential issuance flow. */
    fun startIssuance(
        offer: String? = null,
        credentialOfferUri: String? = null,
        redirectUri: String? = null,
    ) {
        send(FlowStartMessage.serializer(), FlowStartMessage(
            protocol = "oid4vci",
            offer = offer,
            credentialOfferUri = credentialOfferUri,
            redirectUri = redirectUri,
        ))
    }

    /** Start an OID4VP credential presentation flow. */
    fun startPresentation(
        requestUri: String? = null,
        requestUriRef: String? = null,
    ) {
        send(FlowStartMessage.serializer(), FlowStartMessage(
            protocol = "oid4vp",
            requestUri = requestUri,
            requestUriRef = requestUriRef,
        ))
    }

    /** Cancel an in-progress flow by sending a decline action. */
    fun cancelFlow(flowId: String) {
        sendFlowAction(flowId, "decline", kotlinx.serialization.json.buildJsonObject {
            put("reason", kotlinx.serialization.json.JsonPrimitive("user_cancelled"))
        })
    }

    /** Send a flow action (consent, select_credential, etc.). */
    fun sendFlowAction(flowId: String, action: String, payload: JsonObject? = null) {
        send(FlowActionMessage.serializer(), FlowActionMessage(
            flowId = flowId,
            action = action,
            payload = payload,
            timestamp = java.time.Instant.now().toString(),
        ))
    }

    /** Send a signing response back to the server. */
    fun sendSignResponse(
        flowId: String,
        proofJwt: String? = null,
        vpToken: String? = null,
        proofs: List<ProofObject>? = null,
        messageId: String? = null,
    ) {
        send(SignResponseMessage.serializer(), SignResponseMessage(
            flowId = flowId,
            messageId = messageId,
            proofJwt = proofJwt,
            vpToken = vpToken,
            proofs = proofs,
        ))
    }

    /** Send a credential matching response back to the server. */
    fun sendMatchResponse(flowId: String, matches: List<CredentialMatch>) {
        send(MatchResponseMessage.serializer(), MatchResponseMessage(
            flowId = flowId,
            matches = matches,
        ))
    }

    /** Send a trust evaluation result back to the server. */
    fun sendTrustResult(flowId: String, trusted: Boolean, reason: String? = null) {
        val payload = kotlinx.serialization.json.buildJsonObject {
            put("trusted", kotlinx.serialization.json.JsonPrimitive(trusted))
            reason?.let { put("reason", kotlinx.serialization.json.JsonPrimitive(it)) }
        }
        sendFlowAction(
            flowId = flowId,
            action = "trust_result",
            payload = payload,
        )
    }

    /**
     * Send an OID4VCI §10 credential lifecycle notification to the backend,
     * which forwards it to the issuer's notification_endpoint using the
     * ephemeral issuance token. The client supplies the notification_id it
     * received at issuance.
     *
     * This is a no-op when the session is not connected: the notification is
     * triggered automatically after a credential is stored, which may race with
     * a concurrent disconnect (e.g. logout). Dropping it in that case is safe
     * because §10 notifications are optional and best-effort.
     */
    override fun sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String?,
    ) {
        if (!isConnected) return
        send(CredentialNotificationMessage.serializer(), CredentialNotificationMessage(
            flowId = flowId,
            notificationId = notificationId,
            event = event,
            eventDescription = eventDescription,
            timestamp = java.time.Instant.now().toString(),
        ))
    }

    /**
     * Suspend until the engine WebSocket handshake completes or fails.
     * Call this after [connect] to ensure the session is ready before sending messages.
     */
    suspend fun awaitConnected(timeoutMs: Long = 10_000) {
        withTimeout(timeoutMs) {
            state.first { it == State.CONNECTED || it == State.FAILED }
        }
        if (_state.value == State.FAILED) {
            throw IllegalStateException("Engine WebSocket connection failed")
        }
    }

    /** Disconnect the WebSocket session. */
    fun disconnect() {
        lastAppToken = null  // prevent reconnection
        webSocket?.close(1000, "client disconnect")
        webSocket = null
        sessionId = null
        _state.value = State.DISCONNECTED
        // Close all channels to release consumers
        incomingMessages.close()
        flowProgressChannel.close()
        flowCompleteChannel.close()
        flowErrorChannel.close()
        signRequestChannel.close()
        matchRequestChannel.close()
        pushChannel.close()
        notificationAckChannel.close()
        scope.cancel()
    }

    private fun <T> send(serializer: kotlinx.serialization.KSerializer<T>, message: T) {
        val ws = webSocket ?: throw IllegalStateException("Not connected")
        val text = json.encodeToString(serializer, message)
        ws.send(text)
    }

    companion object {
        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .pingInterval(30, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()
    }
}
