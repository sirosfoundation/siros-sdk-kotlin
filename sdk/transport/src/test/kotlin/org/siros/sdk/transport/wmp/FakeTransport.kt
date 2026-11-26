package org.siros.sdk.transport.wmp

import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import org.siros.sdk.transport.Transport
import org.siros.sdk.transport.TransportState

/**
 * In-memory transport for unit testing. Allows sending canned responses
 * and capturing outgoing messages.
 */
class FakeTransport : Transport {
    private val _state = MutableStateFlow(TransportState.DISCONNECTED)
    override val state: StateFlow<TransportState> = _state

    private val _incoming = Channel<ByteArray>(Channel.BUFFERED)
    private val _sent = CopyOnWriteArrayList<ByteArray>()
    val sentMessages: List<ByteArray> get() = _sent.toList()
    val sessionCreatedIds = CopyOnWriteArrayList<String>()

    /**
     * The transport-surface event log, in arrival order (issue #447):
     * `connect`, `disconnect`, `onSessionCreated:<id>`, and
     * `send:<json-rpc method>`. For order-sensitive assertions — which
     * of two operations the caller actually performed first. The payload
     * bytes are never recorded, only the method name.
     */
    val events = CopyOnWriteArrayList<String>()

    override suspend fun connect() {
        events.add("connect")
        _state.value = TransportState.CONNECTED
    }

    override suspend fun onSessionCreated(sessionId: String) {
        events.add("onSessionCreated:$sessionId")
        sessionCreatedIds.add(sessionId)
    }

    override suspend fun send(message: ByteArray) {
        events.add("send:${methodOf(message)}")
        _sent.add(message)
    }

    override fun incoming(): Flow<ByteArray> = _incoming.receiveAsFlow()

    override suspend fun disconnect() {
        events.add("disconnect")
        _state.value = TransportState.DISCONNECTED
    }

    /** The JSON-RPC method of a sent frame, for the event log. */
    private fun methodOf(message: ByteArray): String =
        Regex(""""method"\s*:\s*"([^"]+)"""")
            .find(String(message, Charsets.UTF_8))
            ?.groupValues?.get(1)
            ?: "response"

    /** Simulate receiving a message from the server. */
    suspend fun receiveFromServer(data: ByteArray) {
        _incoming.send(data)
    }

    fun simulateDisconnect() {
        _state.value = TransportState.DISCONNECTED
    }

    fun simulateFailure() {
        _state.value = TransportState.FAILED
    }
}
