package org.siros.sdk.transport

import kotlinx.coroutines.flow.Flow

/**
 * Transport-independent interface for WMP communication.
 * Implementations handle framing and connection lifecycle for a specific
 * transport binding (WebSocket, HTTPS+SSE, in-process, etc.).
 */
interface Transport {
    /** Current connection state. */
    val state: Flow<TransportState>

    /**
     * Connect to the remote endpoint. For the HTTP+SSE binding this opens the
     * event stream ONLY once the session id is known (the engine's SSE route
     * requires `?session_id=`): a [connect] before [onSessionCreated] is a
     * no-op there, deferring to it.
     */
    suspend fun connect()

    /**
     * The session was created (or resumed): its id. The HTTP+SSE binding
     * names its event stream with it (`?session_id=` - the engine routes the
     * stream, its replay and its live events by that id); the WS and
     * in-process bindings need nothing (their carrier is bound another way).
     */
    suspend fun onSessionCreated(sessionId: String) {}

    /** Send a raw JSON-RPC message. */
    suspend fun send(message: ByteArray)

    /** Incoming messages as a flow. */
    fun incoming(): Flow<ByteArray>

    /** Gracefully close the connection. */
    suspend fun disconnect()
}

enum class TransportState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    FAILED,
}
