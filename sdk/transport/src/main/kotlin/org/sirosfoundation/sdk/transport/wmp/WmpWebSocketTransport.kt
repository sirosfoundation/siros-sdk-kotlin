package org.sirosfoundation.sdk.transport.wmp

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.sirosfoundation.sdk.transport.Transport
import org.sirosfoundation.sdk.transport.TransportState
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * WMP WebSocket transport binding.
 * Connects to a WMP endpoint using the `wmp.v1` subprotocol.
 */
class WmpWebSocketTransport(
    private val url: String,
    private val client: OkHttpClient = defaultClient(),
    private val extraHeaders: Map<String, String> = emptyMap(),
) : Transport {

    private val _state = MutableStateFlow(TransportState.DISCONNECTED)
    override val state: StateFlow<TransportState> = _state

    private val incomingChannel = Channel<ByteArray>(Channel.BUFFERED)
    private var webSocket: WebSocket? = null

    override suspend fun connect() {
        if (_state.value == TransportState.CONNECTED) return
        _state.value = TransportState.CONNECTING

        val request = Request.Builder()
            .url(url)
            .header("Sec-WebSocket-Protocol", "wmp.v1")
            .apply { extraHeaders.forEach { (k, v) -> header(k, v) } }
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Timber.d("WebSocket connected to $url")
                _state.value = TransportState.CONNECTED
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val result = incomingChannel.trySend(text.toByteArray(Charsets.UTF_8))
                if (result.isFailure) {
                    Timber.w("Incoming channel full, dropping message")
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Timber.d("WebSocket closing: $code $reason")
                webSocket.close(1000, null)
                _state.value = TransportState.DISCONNECTED
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Timber.e(t, "WebSocket failure")
                _state.value = TransportState.FAILED
            }
        })
    }

    override suspend fun send(message: ByteArray) {
        val ws = webSocket ?: throw IllegalStateException("WebSocket not connected")
        ws.send(message.toString(Charsets.UTF_8))
    }

    override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

    override suspend fun disconnect() {
        webSocket?.close(1000, "client disconnect")
        webSocket = null
        _state.value = TransportState.DISCONNECTED
    }

    companion object {
        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .pingInterval(30, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS) // no read timeout for WebSocket
            .build()
    }
}
