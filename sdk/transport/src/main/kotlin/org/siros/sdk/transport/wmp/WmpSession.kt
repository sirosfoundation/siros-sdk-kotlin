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

    /** The current session's id, when one is live (the join invitation's group name, issue #77). */
    val currentSessionId: String?
        get() = sessionId

    /** The capabilities the live session negotiated, when one exists (the create's answer). */
    val currentCapabilities: JsonObject?
        get() = sessionId?.let { capabilities }
    private var resumptionToken: String? = null

    /** The latest resumption token (rotated on every resume), for persistence. */
    val currentResumptionToken: String?
        get() = resumptionToken

    private var lastReceivedId: String? = null
    // Saved from the create() call so the fresh-create fallback after a
    // resume exhaustion replays the same auth, sender and capabilities.
    private var authToken: String? = null
    private var sender: String? = null
    private var capabilities: JsonObject? = null

    private val pendingRequests = ConcurrentHashMap<String, CompletableDeferred<JsonRpcResponse>>()
    private val incomingNotifications = Channel<JsonRpcRequest>(Channel.BUFFERED)
    private var messageLoopStarted = false

    /** Notifications from the server (flow.progress, flow.complete, etc.). */
    fun notifications(): Flow<JsonRpcRequest> = incomingNotifications.receiveAsFlow()

    /**
     * The engine's answers that mean the wallet's session is GONE server-side
     * (wallet-core#48): `-31000` "Session not found" — the engine restarted or
     * the store swept it — and `-31001` "Session expired" — the record is
     * present but its TTL passed. Both are self-healable the same way: a
     * transparent fresh `create` (the engine session is stateless from the
     * wallet's perspective; the credentials live in the wallet's store, not
     * the engine's). Matched on the message text because the error payload
     * carries the message on every path ([WmpSessionException] embeds it).
     */
    fun isSessionGone(message: String?): Boolean {
        if (message == null) return false
        return message.contains("Session not found") || message.contains("Session expired")
    }

    /**
     * A fresh [create] replaying the saved auth, sender and capabilities —
     * the self-heal after the engine answered session loss (#48). The same
     * call the resume-exhaustion fallback makes; safe to run over a
     * connected transport (`resume` re-`connect`s the same way).
     */
    suspend fun recreate(
        // Issue #77: the invitation this recreate consumes (the session
        // bootstrap after a scan).
        invitationNonce: String? = null,
    ) {
        val token = authToken ?: throw WmpSessionException("No auth token to recreate the session with")
        create(token, sender, capabilities, invitationNonce)
    }

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
        // Issue #77: the invitation nonce this create consumes — the
        // engine's session bootstrap validates it single-use.
        invitationNonce: String? = null,
    ) {
        // Saved for the fresh-create fallback (see handleDisconnect).
        this.authToken = authToken
        this.sender = sender
        this.capabilities = capabilitiesOffered
        _state.value = WmpSessionState.CONNECTING
        transport.connect()
        startMessageLoop()

        val params = codec.encodeParams(
            SessionCreateParams(
                wmp = WmpMeta(sender = sender),
                capabilitiesOffered = capabilitiesOffered,
                // The binding decides the auth type (wmp-core §4.4.6): an
                // mTLS-bound session authenticates by the certificate the
                // transport presents at TLS — `auth.type = "mtls"`, no
                // bearer; otherwise the token the caller handed over.
                auth = if (config.mtlsBinding != null) {
                    SessionAuth(type = "mtls", token = "")
                } else {
                    SessionAuth(type = "bearer", token = authToken)
                },
                ttl = config.sessionTtlSeconds,
                invitationNonce = invitationNonce,
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

    /**
     * Restore a previously persisted session and resume it (after an app
     * restart): seeds the stored session id + token, then runs [resume].
     */
    suspend fun resumeWith(sessionId: String, resumptionToken: String) {
        this.sessionId = sessionId
        this.resumptionToken = resumptionToken
        resume()
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

        // A cold restore has never told the HTTP+SSE transport which session
        // its stream belongs to: resumeWith seeded THIS session, not the
        // transport. Open the stream now, exactly as create does, or the
        // resumed peer can poll but never receives live deliveries.
        transport.onSessionCreated(sid)

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
        // The session is terminal from here on, BEFORE the transport is torn
        // down (#447): the collector below now handles every transport
        // failure regardless of the session's own state, so the resumption
        // token must already be gone when the disconnect's emission reaches
        // it — a closing session must not resume itself.
        sessionId = null
        resumptionToken = null
        transport.disconnect()
        _state.value = WmpSessionState.CLOSED
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
            // The timeout wraps the send AND the await (#417): a request
            // on a severed pooled connection would otherwise hang in the
            // send forever - the timeout cancels the transport's in-flight
            // call (the cancellable form), okhttp evicts the dead
            // connection, and the error surfaces as a retryable
            // WmpTimeoutException instead of an indefinite hang.
            return withTimeout(timeoutMs) {
                withContext(kotlinx.coroutines.Dispatchers.IO) {
                    transport.send(message)
                }
                deferred.await()
            }
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

    @Synchronized
    private fun startMessageLoop() {
        // create, every resume, and every reconnect share this scope. Starting
        // another pair of collectors would make them compete for responses and
        // notifications; one pair owns the transport for the session's life.
        if (messageLoopStarted) return
        messageLoopStarted = true
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
                        // The failure is handled whatever the session's own
                        // state is (#447). The historic ACTIVE-only guard
                        // silently dropped the disconnect whenever the session
                        // sat in RESUMING, CONNECTING or FAILED — found live
                        // (the Cleverbase Echo E2E round): the stream's
                        // liveness deadline marked the transport FAILED while
                        // a resume was still in flight, the collector dropped
                        // it, and no code path ever retried — the wallet
                        // stayed stranded on a dead stream until a
                        // force-stop. The recovery below is safe from any
                        // state: without a resumption token it is a no-op,
                        // and the resume path is idempotent (single-flight).
                        handleDisconnect()
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

    /**
     * The in-flight recovery's single-flight handle (#447): one resume loop
     * runs at a time; a trigger that fires while a recovery is already
     * running — the collector and a stalled request's [recoverTransport]
     * can both react to the same failure — awaits it instead of racing a
     * second resume against it.
     */
    private var inFlightRecovery: CompletableDeferred<Unit>? = null

    /**
     * Claims the recovery: the running flight to await, or null when the
     * caller must run it.
     */
    @Synchronized
    private fun claimRecovery(): CompletableDeferred<Unit>? {
        val running = inFlightRecovery
        if (running != null) return running
        inFlightRecovery = CompletableDeferred()
        return null
    }

    /**
     * The on-demand transport recovery a stalled request triggers
     * (#447): a flow.start whose POST timed out left the SSE stream
     * dead-but-CONNECTED — the half-open socket, where the kernel still
     * shows the connection established and no byte flows — and a bare
     * request retry would orphan the flow AGAIN, because the engine's
     * asks ride the SSE stream, not the POST's connection. Force the
     * stream's teardown FIRST: [Transport.connect] no-ops on a CONNECTED
     * transport, so the resume below would re-attach to the very stream
     * whose silence stalled the request. Then the existing
     * [handleDisconnect] recovery runs — its resume rotates the
     * resumption token and re-opens the stream (`?session_id=` names it,
     * the SSE binding of wmp-transport.md §4.3.4) — and the caller's
     * retry rides the live one. Single-flight with the collector's own
     * trigger on the disconnect this emits: whichever fires first runs
     * the recovery, the other awaits it, so exactly one resume runs.
     */
    internal suspend fun recoverTransport() {
        transport.disconnect()
        handleDisconnect()
    }

    private suspend fun handleDisconnect() {
        // No session to resume yet (pre-create, or already closed): the
        // recovery is a no-op — the guard that makes the collector above
        // safe to run from any session state.
        if (resumptionToken == null) return
        val running = claimRecovery()
        if (running != null) {
            // A recovery is already running for this failure: await it
            // rather than racing a second resume loop against it.
            running.await()
            return
        }
        val flight = inFlightRecovery
        try {
            // A stale trigger (#447): the transport reconnected — or is
            // reconnecting — while this trigger waited its turn (the
            // single-flight's other runner, or a concurrent resume), so
            // the recovery it asks for already happened. The collector's
            // emissions conflate, but the live state does not: if the
            // transport failed again since, the collector delivers that
            // failure next and the recovery runs then. A transport that
            // does not expose its state as a StateFlow keeps the historic
            // behavior — always recover.
            val live = (transport.state as? StateFlow<TransportState>)?.value
            if (live != null && live != TransportState.DISCONNECTED && live != TransportState.FAILED) return
            _state.value = WmpSessionState.RESUMING

            var attempt = 0
            var lastError: Exception? = null
            while (attempt < config.maxReconnectAttempts) {
                attempt++
                val backoffMs = min(config.reconnectBaseMs * (1L shl attempt), config.reconnectMaxMs)
                Timber.i("WMP reconnect attempt $attempt in ${backoffMs}ms")
                delay(backoffMs)

                try {
                    resume()
                    return
                } catch (e: Exception) {
                    lastError = e
                    Timber.w(e, "Reconnect attempt $attempt failed")
                }
            }

            // The resume exhausted. A session-gone answer ("Session not found"
            // for a swept/restarted session, "Session expired" for a present
            // record whose TTL passed — #48: the wallet sat in the background
            // past the engine's session TTL) means it is GONE, and trying to
            // resume again in 30 seconds is trying to bring back the dead.
            // The wallet's engine session is stateless from its own
            // perspective (the credentials live in the wallet's store, not
            // the engine's), so a transparent fresh create is safe and the
            // wallet never gets stranded on a dead session. Found on-device
            // against the GDC released engine: the session's TTL lapsed
            // while the wallet sat in the background, the resume loop
            // exhausted, and every later QR scan's flow start landed on
            // the dead session - the engine answered "Capability not
            // supported" (the capability gate fires on an unresolvable
            // session before the flow's own matching, so every request
            // failed identically regardless of which credential it named).
            // The original cut matched only "Session not found", so the
            // TTL-expiry answer ("Session expired") fell through to FAILED
            // and every later flow start surfaced its error - the recovery
            // the #48 fix re-found on-device.
            if (isSessionGone(lastError?.message) && authToken != null) {
                Timber.i("Session expired on the server; creating a fresh session")
                try {
                    create(authToken!!, sender, capabilities)
                    return
                } catch (e: Exception) {
                    Timber.e(e, "Fresh session creation after resume exhaustion failed")
                }
            }

            _state.value = WmpSessionState.FAILED
            pendingRequests.values.forEach { it.cancel() }
            pendingRequests.clear()
        } finally {
            // Release the single-flight BEFORE waking the waiters: a trigger
            // arriving after the reset starts a fresh recovery of its own,
            // while the ones already awaiting this flight return (#447).
            synchronized(this) { inFlightRecovery = null }
            flight?.complete(Unit)
        }
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
    /**
     * The session create's requested TTL, seconds. **Null (the default)
     * omits the `ttl` member** so the engine's own default applies — an
     * explicit value overrides it (the reference engine caps it at its
     * max). The old 3600 default reaped live join sessions at one hour
     * against engines defaulting to days (found live: golden-fox,
     * 2026-11-25 — the join session died at its ttl while the inviter's
     * carried 24h, and the group vanished on restart).
     */
    val sessionTtlSeconds: Int? = null,
    val requestTimeoutMs: Long = 30_000,
    val maxReconnectAttempts: Int = 10,
    val reconnectBaseMs: Long = 1_000,
    val reconnectMaxMs: Long = 30_000,
    /**
     * The mTLS session binding (wmp-core §4.4.6: the `ebcore` scheme
     * authenticates with `mtls` — the subscriber certificate presented at
     * the TLS level; wmp-transport §4.3.1: the session binds to the
     * authenticated principal). When set, the session create sends
     * `auth.type = "mtls"` (no bearer) and the transport presents the
     * certificate on every request of the binding — the load balancer
     * verifies it and forwards the binding the middleware authorizes.
     *
     * Null (the default) keeps the bearer binding.
     */
    val mtlsBinding: MtlsBinding? = null,
)

/**
 * The mTLS binding's credential pair: the subscriber certificate chain and
 * its private key, both PEM. The certificate PEM carries the **full chain,
 * leaf first** (the leaf, then the issuing CA(s)) — the load balancer needs
 * the CA to validate the leaf against its trust anchor, so the chain must
 * ride every handshake (found live: the leaf alone left the LB unable to
 * bind the session to the identity). The key never leaves the client.
 *
 * The PEM pair is the held-key form (a plain key file or an app-managed
 * secret); a keystore-backed form can wrap the same config surface later —
 * the gate's shape is the pair, not the storage.
 */
data class MtlsBinding(
    /** The subscriber certificate chain, leaf first, then the CA(s). */
    val certificatePem: String,
    val privateKeyPem: String,
)

class WmpSessionException(message: String, cause: Throwable? = null) : org.siros.sdk.credentials.SirosException(message, cause)
class WmpTimeoutException(message: String) : org.siros.sdk.credentials.SirosException(message)
