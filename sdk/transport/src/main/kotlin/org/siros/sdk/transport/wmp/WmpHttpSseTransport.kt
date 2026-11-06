// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.siros.sdk.transport.Transport
import org.siros.sdk.transport.TransportState
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
 * @param tokenProvider Freshens the `Authorization` bearer per request: the
 *   HTTP+SSE binding is stateless - EVERY POST is its own request and the
 *   engine validates each one against the AS - so a token baked in at
 *   connect dies with its (typically ~120 s) expiry and every later POST is
 *   answered "Not authorized" (found driving an issuance ~40 minutes after
 *   login: the start reached the engine with a long-expired token). The
 *   provider is called per POST and per SSE (re)connect; the wallet's is
 *   `ensure`-shaped (cached until expired), so the calls are cheap. A null
 *   return falls back to no Authorization header; extraHeaders'
 *   Authorization (if any) then applies. Takes precedence over extraHeaders'
 *   Authorization when both answer.
 */
class WmpHttpSseTransport(
    private val sendUrl: String,
    private val sseUrl: String,
    private val client: OkHttpClient = defaultClient(),
    private val extraHeaders: Map<String, String> = emptyMap(),
    private val tokenProvider: (suspend () -> String?)? = null,
) : Transport {

    private val _state = MutableStateFlow(TransportState.DISCONNECTED)
    override val state: StateFlow<TransportState> = _state

    private val incomingChannel = Channel<ByteArray>(Channel.BUFFERED)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var sseJob: Job? = null

    /** The ids of the events already delivered (bounded): a replayed event with the same `id:` is dropped, not delivered twice. */
    private val seenEventIds = object : LinkedHashSet<String>() {}
    @Volatile private var lastEventId: String? = null

    /**
     * The request headers for one outgoing request: [extraHeaders], with the
     * `Authorization` freshened from [tokenProvider] when it answers (see its
     * doc comment for why per-request, not per-connect).
     */
    private suspend fun requestHeaders(): Map<String, String> {
        val headers = extraHeaders.toMutableMap()
        val token = tokenProvider?.invoke()
        if (token != null) headers["Authorization"] = "Bearer $token"
        return headers
    }

    /**
     * Opens the event stream and returns only once it is CONNECTED (or has failed): a caller that sends a request
     * right after `connect()` therefore never sends before the stream is open. That matters for a flow that delivers
     * a secret, which is delivered live and once to the stream connected when it is emitted (OpenID4VCI 1.1
     * response-level `credential_metadata`, privatedata-spec 5A), so the stream MUST be up before `wmp.flow.start`.
     * On a reconnect `Last-Event-ID` carries the last event received.
     */
    override suspend fun connect() {
        if (_state.value == TransportState.CONNECTED) return
        _state.value = TransportState.CONNECTING

        val request = Request.Builder()
            .url(sseUrl)
            .apply { requestHeaders().forEach { (k, v) -> header(k, v) } }
            .header("Accept", "text/event-stream")
            .apply { lastEventId?.let { header("Last-Event-ID", it) } }
            .build()

        val opened = kotlinx.coroutines.CompletableDeferred<Unit>()
        sseJob = scope.launch {
            try {
                val response = client.newCall(request).execute()
                if (!response.isSuccessful) {
                    Timber.e("SSE connection failed: ${response.code}")
                    _state.value = TransportState.FAILED
                    opened.complete(Unit)
                    return@launch
                }

                _state.value = TransportState.CONNECTED
                opened.complete(Unit)
                Timber.d("SSE connected to $sseUrl")

                val reader = BufferedReader(InputStreamReader(response.body!!.byteStream()))
                var currentData = StringBuilder()
                var currentId: String? = null

                while (true) {
                    val line = reader.readLine() ?: break

                    when {
                        line.isEmpty() -> {
                            // Empty line = end of event, dispatch (once per event id)
                            val data = currentData.toString()
                            val id = currentId
                            if (data.isNotEmpty() && (id == null || markSeen(id))) {
                                incomingChannel.trySend(data.toByteArray(Charsets.UTF_8))
                            }
                            if (id != null) lastEventId = id
                            currentData = StringBuilder()
                            currentId = null
                        }
                        line.startsWith("data: ") -> {
                            if (currentData.isNotEmpty()) currentData.append('\n')
                            currentData.append(line.removePrefix("data: "))
                        }
                        line.startsWith("id:") -> currentId = line.removePrefix("id:").trim().takeIf { it.isNotEmpty() }
                        // Ignore event:, retry:, comments (:). The data of an event is never logged.
                    }
                }

                _state.value = TransportState.DISCONNECTED
            } catch (e: Exception) {
                if (_state.value != TransportState.DISCONNECTED) {
                    Timber.e("SSE error (${e.javaClass.simpleName})")
                    _state.value = TransportState.FAILED
                }
                opened.complete(Unit)
            }
        }
        opened.await()
    }

    /** True the first time [id] is seen; a replay of the same event id is false. Bounded. */
    @Synchronized
    private fun markSeen(id: String): Boolean {
        if (!seenEventIds.add(id)) return false
        if (seenEventIds.size > MAX_SEEN_EVENT_IDS) seenEventIds.remove(seenEventIds.first())
        return true
    }

    override suspend fun send(message: ByteArray) {
        val request = Request.Builder()
            .url(sendUrl)
            .apply { requestHeaders().forEach { (k, v) -> header(k, v) } }
            .post(message.toRequestBody("application/json".toMediaType()))
            .build()

        // OkHttp's execute() is a blocking call - hop to the IO dispatcher
        // so a caller on the main thread (the wallet's connect path is
        // invoked there) doesn't crash with NetworkOnMainThreadException
        // (found driving the HTTP+SSE mode against a live engine). The SSE
        // side already runs in [scope] (Dispatchers.IO).
        withContext(Dispatchers.IO) {
            client.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) {
                    throw WmpSessionException("HTTP POST failed: ${resp.code} ${resp.message}")
                }
                // The binding is request/response OVER SSE: the POST's own
                // HTTP response is empty (204 No Content); the JSON-RPC
                // reply rides the SSE stream. Some deployments (proxies,
                // an early-reply engine) answer the POST body directly - so
                // deliver it to the incoming channel when there is one,
                // never discarding a reply (found driving against a live
                // engine: the session create answered, the transport threw
                // it away, and every request timed out).
                val body: ByteArray = resp.body?.bytes() ?: ByteArray(0)
                if (body.isNotEmpty()) {
                    incomingChannel.trySend(body)
                }
            }
        }
    }

    override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

    override suspend fun disconnect() {
        sseJob?.cancel()
        sseJob = null
        _state.value = TransportState.DISCONNECTED
    }

    companion object {
        private const val MAX_SEEN_EVENT_IDS = 4096

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS) // no read timeout for SSE
            .connectTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
