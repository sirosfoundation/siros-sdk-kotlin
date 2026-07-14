// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.transport.wmp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.sirosfoundation.sdk.transport.Transport
import org.sirosfoundation.sdk.transport.TransportState
import timber.log.Timber
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * WMP HTTP+SSE transport binding.
 *
 * Uses HTTP POST for sending messages and Server-Sent Events (SSE) for
 * receiving messages. This is useful for environments where WebSocket
 * connections are blocked by firewalls or corporate proxies.
 *
 * @param sendUrl The URL for HTTP POST (outgoing messages).
 * @param sseUrl The URL for SSE EventSource (incoming messages).
 * @param client Optional OkHttpClient (shared with other SDK components).
 * @param extraHeaders Additional headers (e.g., Authorization, X-Tenant-ID).
 */
class WmpHttpSseTransport(
    private val sendUrl: String,
    private val sseUrl: String,
    private val client: OkHttpClient = defaultClient(),
    private val extraHeaders: Map<String, String> = emptyMap(),
) : Transport {

    private val _state = MutableStateFlow(TransportState.DISCONNECTED)
    override val state: StateFlow<TransportState> = _state

    private val incomingChannel = Channel<ByteArray>(Channel.BUFFERED)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var sseJob: Job? = null

    override suspend fun connect() {
        if (_state.value == TransportState.CONNECTED) return
        _state.value = TransportState.CONNECTING

        val request = Request.Builder()
            .url(sseUrl)
            .apply { extraHeaders.forEach { (k, v) -> header(k, v) } }
            .header("Accept", "text/event-stream")
            .build()

        sseJob = scope.launch {
            try {
                val response = client.newCall(request).execute()
                if (!response.isSuccessful) {
                    Timber.e("SSE connection failed: ${response.code}")
                    _state.value = TransportState.FAILED
                    return@launch
                }

                _state.value = TransportState.CONNECTED
                Timber.d("SSE connected to $sseUrl")

                val reader = BufferedReader(InputStreamReader(response.body!!.byteStream()))
                var currentData = StringBuilder()

                while (true) {
                    val line = reader.readLine() ?: break

                    when {
                        line.isEmpty() -> {
                            // Empty line = end of event, dispatch
                            val data = currentData.toString()
                            if (data.isNotEmpty()) {
                                incomingChannel.trySend(data.toByteArray(Charsets.UTF_8))
                            }
                            currentData = StringBuilder()
                        }
                        line.startsWith("data: ") -> {
                            if (currentData.isNotEmpty()) currentData.append('\n')
                            currentData.append(line.removePrefix("data: "))
                        }
                        // Ignore event:, id:, retry:, comments (:)
                    }
                }

                _state.value = TransportState.DISCONNECTED
            } catch (e: Exception) {
                if (_state.value != TransportState.DISCONNECTED) {
                    Timber.e(e, "SSE error")
                    _state.value = TransportState.FAILED
                }
            }
        }
    }

    override suspend fun send(message: ByteArray) {
        val request = Request.Builder()
            .url(sendUrl)
            .apply { extraHeaders.forEach { (k, v) -> header(k, v) } }
            .header("Content-Type", "application/json")
            .post(message.toString(Charsets.UTF_8).toRequestBody("application/json".toMediaType()))
            .build()

        val response = client.newCall(request).execute()
        if (!response.isSuccessful) {
            throw WmpSessionException("HTTP POST failed: ${response.code} ${response.message}")
        }
        response.close()
    }

    override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

    override suspend fun disconnect() {
        sseJob?.cancel()
        sseJob = null
        _state.value = TransportState.DISCONNECTED
    }

    companion object {
        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS) // no read timeout for SSE
            .connectTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
