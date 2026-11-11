package org.siros.sdk.transport.wmp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.transport.Transport
import org.siros.sdk.transport.TransportState
import timber.log.Timber
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * WMP session client managing a single session over a [Transport].
 *
 * Handles session lifecycle (create/resume/close), request-response correlation,
 * and automatic reconnection with session resumption.
 */
class WmpSession(
    private val transport: Transport,
    internal val codec: WmpCodec = WmpCodec(),
    private val config: WmpSessionConfig = WmpSessionConfig(),
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _state = MutableStateFlow(WmpSessionState.CLOSED)
    val state: StateFlow<WmpSessionState> = _state

    private var sessionId: String? = null
    private var resumptionToken: String? = null
    private var lastReceivedId: String? = null

    private val pendingRequests = ConcurrentHashMap<String, CompletableDeferred<JsonRpcResponse>>()
    private val incomingNotifications = Channel<JsonRpcRequest>(Channel.BUFFERED)

    /** Notifications from the server (flow.progress, flow.complete, etc.). */
    fun notifications(): Flow<JsonRpcRequest> = incomingNotifications.receiveAsFlow()

    /**
     * Create a new WMP session with the given auth token.
     *
     * @param capabilitiesOffered the capabilities this wallet offers
     *   (`capabilities_offered`), by name. Capabilities are offered per
     *   session: changing what a wallet supports takes effect only on a new
     *   session. `null` offers none.
     */
    suspend fun create(
        authToken: String,
        sender: String? = null,
        capabilitiesOffered: JsonObject? = null,
    ) {
        _state.value = WmpSessionState.CONNECTING
        transport.connect()
        startMessageLoop()

        val params = codec.encodeParams(
            SessionCreateParams(
                wmp = WmpMeta(sender = sender),
                capabilitiesOffered = capabilitiesOffered,
                auth = SessionAuth(type = "bearer", token = authToken),
                ttl = config.sessionTtlSeconds,
            )
        )

        val response = sendRequest("wmp.session.create", params)
        if (response.error != null) {
            _state.value = WmpSessionState.FAILED
            throw WmpSessionException("Session creation failed: ${response.error.message}")
        }

        val result = response.result
            ?: throw WmpSessionException("Session creation response missing result")
        val parsed = codec.json.decodeFromJsonElement(
            SessionCreateResult.serializer(),
            result,
        )

        sessionId = parsed.wmp.sessionId
        resumptionToken = parsed.resumptionToken

        // The HTTP+SSE binding names its event stream with the session id (the
        // engine's SSE route requires `?session_id=`): it opens HERE, after
        // the create answered. The create's own reply rode the POST's body.
        // The WS and in-process bindings answer nothing (their carrier is
        // bound another way).
        transport.onSessionCreated(sessionId!!)

        _state.value = WmpSessionState.ACTIVE
        Timber.i("WMP session created: $sessionId")
    }

    /** Resume an existing session after reconnection. */
    suspend fun resume() {
        val sid = sessionId ?: throw WmpSessionException("No session to resume")
        val token = resumptionToken ?: throw WmpSessionException("No resumption token")

        _state.value = WmpSessionState.RESUMING
        transport.connect()
        startMessageLoop()

        val params = codec.encodeParams(
            SessionResumeParams(
                wmp = WmpMeta(sessionId = sid),
                sessionId = sid,
                resumptionToken = token,
                lastReceivedId = lastReceivedId,
            )
        )

        val response = sendRequest("wmp.session.resume", params)
        if (response.error != null) {
            _state.value = WmpSessionState.FAILED
            throw WmpSessionException("Session resume failed: ${response.error.message}")
        }

        // The resumption token ROTATES on every resume (single-use, go-wmp
        // SessionService semantics): the next resume - and there will be one,
        // the SSE stream drops whenever Android backgrounds the app - must
        // present THIS one, not the (already-spent) token this resume
        // consumed. Found driving the GDC issuance: every reconnect after a
        // browser round-trip re-POSTed the same spent token and was answered
        // -31000 "Session not found", forever (the "Initializing…" hang).
        val result = response.result?.let {
            try {
                codec.json.decodeFromJsonElement(SessionResumeResult.serializer(), it)
            } catch (e: Exception) {
                null
            }
        }
        if (result?.resumptionToken != null) {
            resumptionToken = result.resumptionToken
        }

        _state.value = WmpSessionState.ACTIVE
        Timber.i("WMP session resumed: $sessionId")
    }

    /** Close the session gracefully. */
    suspend fun close(reason: String = "complete") {
        val sid = sessionId ?: return

        val params = codec.encodeParams(
            SessionCloseParams(
                wmp = WmpMeta(sessionId = sid),
                reason = reason,
            )
        )

        sendNotification("wmp.session.close", params)
        transport.disconnect()
        _state.value = WmpSessionState.CLOSED
        sessionId = null
        resumptionToken = null
        scope.cancel()
        Timber.i("WMP session closed: $sid")
    }

    /**
     * [params] with this session's id stamped into its `wmp.session_id`.
     *
     * The engine resolves EVERY request's session context from that member
     * (the SSE stream aside, the HTTP+SSE binding is stateless - nothing else
     * names the session a POST belongs to), and its capability gate fails
     * closed without one: a flow start whose envelope carried the explicit
     * `null` this SDK's codec writes was answered "Capability not supported"
     * (found driving the issuance). Null before the create answered ([sessionId]
     * unset): the params ride as built. The resume/close envelopes already name
     * the session; the stamp is idempotent over them.
     */
    private fun stampSessionId(params: kotlinx.serialization.json.JsonObject?): kotlinx.serialization.json.JsonObject? {
        val sid = sessionId ?: return params
        val wmp = (params?.get("wmp") as? kotlinx.serialization.json.JsonObject) ?: return params
        return kotlinx.serialization.json.buildJsonObject {
            params.forEach { (key, value) ->
                if (key != "wmp") put(key, value)
            }
            put("wmp", kotlinx.serialization.json.buildJsonObject {
                wmp.forEach { (key, value) -> put(key, value) }
                put("session_id", kotlinx.serialization.json.JsonPrimitive(sid))
            })
        }
    }

    /**
     * Send a JSON-RPC request and wait for the correlated response.
     * Throws [WmpTimeoutException] if the response is not received within the timeout.
     */
    suspend fun sendRequest(
        method: String,
        params: kotlinx.serialization.json.JsonObject?,
        timeoutMs: Long = config.requestTimeoutMs,
    ): JsonRpcResponse {
        val id = UUID.randomUUID().toString()
        val deferred = CompletableDeferred<JsonRpcResponse>()
        pendingRequests[id] = deferred

        try {
            val message = codec.encodeRequest(method, stampSessionId(params), id)
            // NO mutex around the POST (drive-found deadlock): the HTTP+SSE binding
            // is request/response per POST, correlation is by JSON-RPC id, and OkHttp
            // pools connections - serializing sends made a flow start (whose POST
            // stays open for the engine's whole synchronous start - offer, metadata,
            // trust, the PAR push - tens of seconds) hold the lock while the engine
            // WAITED for ask answers queued behind that same lock. The engine's asks
            // timed out, the UI hung on "Initializing", and the authorize action after
            // the browser was stranded. Each send is on its own; ordering was never
            // a wire requirement on this transport.
            //
            // And OFF the caller's thread (the main-dispatcher flavour of the same
            // deadlock, found on-device with the LOCAL engine): the in-process
            // transport's send is a synchronous FFI call that runs the engine's
            // whole flow start - parse, fetch, trust, the MATCH and CONSENT asks -
            // on the CALLING thread. Called from the UI's viewModelScope that is
            // Main: a flow start whose consent ask waits for the user deadlocks
            // against the very thread that must render the consent sheet (found:
            // the GDC presentation - the flow hung at the match, the sheet never
            // rendered, the app froze). The blocking send belongs on IO.
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                transport.send(message)
            }
            return withTimeout(timeoutMs) { deferred.await() }
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            Timber.w("sendRequest: $method id=$id TIMED OUT after ${timeoutMs}ms")
            pendingRequests.remove(id)
            throw WmpTimeoutException("Request $method timed out after ${timeoutMs}ms")
        }
    }

    /** Send a JSON-RPC notification (no response expected). */
    suspend fun sendNotification(method: String, params: kotlinx.serialization.json.JsonObject?) {
        // No mutex - see sendRequest's drive-found note: a locked send serialized
        // answers behind slow POSTs and deadlocked the asks against the start.
        val message = codec.encodeNotification(method, stampSessionId(params))
        // IO, sendRequest's own rule: the in-process transport's send blocks the
        // calling thread in the engine.
        withContext(kotlinx.coroutines.Dispatchers.IO) {
            transport.send(message)
        }
    }

    /** [sendNotification] that checks [wanted] again once it holds the send lock; false when it was not sent. */
    internal suspend fun sendNotificationIf(
        method: String,
        params: kotlinx.serialization.json.JsonObject?,
        wanted: () -> Boolean,
    ): Boolean {
        // No mutex (see sendRequest's drive-found note). The wanted() check and the
        // send are no longer one critical section: a check that passes here can be
        // stale by the time the POST lands - acceptable, the receiver re-checks
        // (the profile's answer machinery ignores answers for ended sub-flows).
        val message = codec.encodeNotification(method, stampSessionId(params))
        if (!wanted()) {
            return false
        }
        transport.send(message)
        return true
    }

    /**
     * Send a JSON-RPC 2.0 response for a server-initiated request.
     * Used when the peer acts as the responder for inbound requests.
     */
    internal suspend fun sendResponse(id: String, result: kotlinx.serialization.json.JsonObject?) {
        val response = JsonRpcResponse(id = id, result = result)
        val message = codec.json.encodeToString(JsonRpcResponse.serializer(), response).toByteArray(Charsets.UTF_8)
        // No mutex - see sendRequest's drive-found note.
        transport.send(message)
    }

    /**
     * Send a JSON-RPC 2.0 error response for a server-initiated request.
     * Used when the peer cannot handle an inbound request.
     *
     * @param id The JSON-RPC request id to correlate the error with.
     * @param code A JSON-RPC / WMP error code (see [WmpErrorCodes]).
     * @param message A human-readable description of the error.
     */
    internal suspend fun sendErrorResponse(id: String, code: Int, message: String) {
        val response = JsonRpcResponse(id = id, error = JsonRpcError(code = code, message = message))
        val msg = codec.json.encodeToString(JsonRpcResponse.serializer(), response).toByteArray(Charsets.UTF_8)
        // No mutex - see sendRequest's drive-found note.
        transport.send(msg)
    }

    private fun startMessageLoop() {
        scope.launch {
            transport.incoming().collect { data ->
                try {
                    handleIncoming(data)
                } catch (e: Exception) {
                    // Never the exception itself: a decode error can quote the frame (a completion may hold a secret).
                    Timber.e("Error handling incoming WMP message (${e.javaClass.simpleName})")
                }
            }
        }

        scope.launch {
            transport.state.collect { transportState ->
                when (transportState) {
                    TransportState.DISCONNECTED, TransportState.FAILED -> {
                        if (_state.value == WmpSessionState.ACTIVE) {
                            handleDisconnect()
                        }
                    }
                    else -> {} // no-op
                }
            }
        }
    }

    private suspend fun handleIncoming(data: ByteArray) {
        when (val message = codec.decodeMessage(data)) {
            is WmpMessage.Response -> {
                val id = message.response.id
                if (id != null) {
                    pendingRequests.remove(id)?.complete(message.response)
                        ?: Timber.w("Received response for unknown request: $id")
                }
            }
            is WmpMessage.Notification -> {
                message.notification.id?.let { lastReceivedId = it }
                incomingNotifications.send(message.notification)
            }
            is WmpMessage.Request -> {
                message.request.id?.let { lastReceivedId = it }
                incomingNotifications.send(message.request)
            }
        }
    }

    private suspend fun handleDisconnect() {
        if (resumptionToken == null) return
        _state.value = WmpSessionState.RESUMING

        var attempt = 0
        while (attempt < config.maxReconnectAttempts) {
            attempt++
            val backoffMs = min(config.reconnectBaseMs * (1L shl attempt), config.reconnectMaxMs)
            Timber.i("WMP reconnect attempt $attempt in ${backoffMs}ms")
            delay(backoffMs)

            try {
                resume()
                return
            } catch (e: Exception) {
                Timber.w(e, "Reconnect attempt $attempt failed")
            }
        }

        _state.value = WmpSessionState.FAILED
        pendingRequests.values.forEach { it.cancel() }
        pendingRequests.clear()
    }
}

enum class WmpSessionState {
    CLOSED,
    CONNECTING,
    ACTIVE,
    RESUMING,
    FAILED,
}

data class WmpSessionConfig(
    val sessionTtlSeconds: Int = 3600,
    val requestTimeoutMs: Long = 30_000,
    val maxReconnectAttempts: Int = 10,
    val reconnectBaseMs: Long = 1_000,
    val reconnectMaxMs: Long = 30_000,
)

class WmpSessionException(message: String, cause: Throwable? = null) : org.siros.sdk.credentials.SirosException(message, cause)
class WmpTimeoutException(message: String) : org.siros.sdk.credentials.SirosException(message)
