package org.sirosfoundation.sdk.transport

import kotlinx.coroutines.flow.Flow

/**
 * Transport-independent interface for WMP communication.
 * Implementations handle framing and connection lifecycle for a specific
 * transport binding (WebSocket, HTTPS+SSE, in-process, etc.).
 */
interface Transport {
    /** Current connection state. */
    val state: Flow<TransportState>

    /** Connect to the remote endpoint. */
    suspend fun connect()

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
