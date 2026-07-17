package org.sirosfoundation.sdk.transport.wmp

import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import org.sirosfoundation.sdk.transport.Transport
import org.sirosfoundation.sdk.transport.TransportState

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

    override suspend fun connect() {
        _state.value = TransportState.CONNECTED
    }

    override suspend fun send(message: ByteArray) {
        _sent.add(message)
    }

    override fun incoming(): Flow<ByteArray> = _incoming.receiveAsFlow()

    override suspend fun disconnect() {
        _state.value = TransportState.DISCONNECTED
    }

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
