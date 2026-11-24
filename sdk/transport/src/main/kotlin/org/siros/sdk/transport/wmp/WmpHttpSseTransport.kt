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
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
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

    /**
     * The SSE stream's OWN client: [client] with a read timeout slightly
     * above the engine's heartbeat cadence — the liveness deadline. The
     * engine heartbeats the stream every ~15s (`:` comment lines), so a
     * read blocking longer than this without ANY byte is a black-holed
     * connection (a carrier NAT idle timeout, Android doze, a proxy that
     * dropped the TCP session without RST) — not a quiet server. The
     * default's `readTimeout(0)` (correct for the request calls) would block
     * `readLine()` forever on the half-open socket: the state stays
     * CONNECTED and every RPC then hangs with no SSE line and no error
     * (found on-device 2026-11-14: the app sat ~8h idle, the stream died
     * silently, the next flow.start hung on "contacting verifier" forever).
     * The timeout throws SocketTimeoutException into the connect loop's
     * catch → FAILED → the session's reconnect replays from
     * Last-Event-ID. 60s = four missed heartbeats.
     */
    private val streamClient: OkHttpClient =
        client.newBuilder().readTimeout(60, TimeUnit.SECONDS).build()

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
     * The session this stream belongs to, from [onSessionCreated]. The engine's
     * SSE route REQUIRES `?session_id=` (it routes the replay and the live
     * events by it), so the stream cannot open before the create answers -
     * [connect] defers to [onSessionCreated] until the id arrives, and every
     * later (re)connect (a resume, a drop) re-opens with it.
     */
    @Volatile private var sseSessionId: String? = null

    /**
     * A pre-create [connect] cannot open the stream: the engine's SSE route
     * answers 400 without `?session_id=`, and no session exists yet anyway.
     * [onSessionCreated] opens it once the create answered; a resume
     * re-connects through here with the remembered id.
     */
    override suspend fun connect() {
        if (_state.value == TransportState.CONNECTED) return
        if (sseSessionId == null) return
        openStream()
    }

    /** The stream, opened with the session the wallet created: `?session_id=` names it (the engine routes by it). */
    override suspend fun onSessionCreated(sessionId: String) {
        val previous = sseSessionId
        sseSessionId = sessionId
        when {
            // The first create: open the stream on it.
            previous == null -> if (_state.value != TransportState.CONNECTED) openStream()
            // A re-create minted a NEW session id (the re-scan path,
            // [WmpSession.recreate] — a second invitation consume on a live
            // peer): the old stream still names the RETIRED id, and the
            // engine routes every event by `?session_id=` — the new
            // session's outbox pushes never reach it. Found live: a second
            // scan of a re-minted invite left the wallet deaf to its group
            // (heartbeats flowed, zero data lines, the inbox never filled).
            // Close the retired stream and open on the fresh id, with fresh
            // event state: the engine's replay then re-delivers everything
            // the new session's mailbox holds from the top.
            previous != sessionId -> {
                sseJob?.cancel()
                sseJob = null
                lastEventId = null
                seenEventIds.clear()
                _state.value = TransportState.DISCONNECTED
                openStream()
            }
            // The same id again (a recreate that answered it): the stream
            // stays as it is.
            else -> if (_state.value != TransportState.CONNECTED) openStream()
        }
    }

    /** The SSE GET, named with the session id. */
    private fun sseRequestUrl(): String {
        val id = sseSessionId ?: return sseUrl
        val separator = if ('?' in sseUrl) "&" else "?"
        return "$sseUrl${separator}session_id=$id"
    }

    /**
     * Opens the event stream and returns only once it is CONNECTED (or has failed): a caller that sends a request
     * right after `connect()` therefore never sends before the stream is open. That matters for a flow that delivers
     * a secret, which is delivered live and once to the stream connected when it is emitted (OpenID4VCI 1.1
     * response-level `credential_metadata`, privatedata-spec 5A), so the stream MUST be up before `wmp.flow.start`.
     * On a reconnect `Last-Event-ID` carries the last event received.
     */
    private suspend fun openStream() {
        if (_state.value == TransportState.CONNECTED) return
        _state.value = TransportState.CONNECTING

        val request = Request.Builder()
            .url(sseRequestUrl())
            .apply { requestHeaders().forEach { (k, v) -> header(k, v) } }
            .header("Accept", "text/event-stream")
            .apply { lastEventId?.let { header("Last-Event-ID", it) } }
            .build()

        val opened = kotlinx.coroutines.CompletableDeferred<Unit>()
        sseJob = scope.launch {
            try {
                // streamClient (not client): the SSE call carries its own read
                // timeout — the liveness deadline, see its declaration.
                val response = streamClient.newCall(request).execute()
                if (!response.isSuccessful) {
                    Timber.e("SSE connection failed: ${response.code}")
                    _state.value = TransportState.FAILED
                    opened.complete(Unit)
                    return@launch
                }

                _state.value = TransportState.CONNECTED
                opened.complete(Unit)
                Timber.d("SSE connected to $sseUrl")

                // The liveness deadline rides the SSE call's OWN client: a
                // per-call builder with a read timeout slightly above the
                // engine's heartbeat cadence. The engine heartbeats the
                // stream every ~15s (`:` comment lines), so a read blocking
                // this long without ANY byte is a black-holed connection (a
                // carrier NAT idle timeout, Android doze, a proxy that
                // dropped the TCP session without RST) — not a quiet server.
                // The default client's readTimeout(0) (no timeout, correct for
                // the OTHER calls) would block readLine() forever on the
                // half-open socket: the state stays CONNECTED and every RPC
                // then hangs with no SSE line and no error (found on-device
                // 2026-11-14: the app sat ~8h idle, the stream died
                // silently, the next flow.start hung "contacting verifier"
                // forever). A SocketTimeoutException here lands in the
                // catch below → FAILED → the session's reconnect replays
                // from Last-Event-ID.
                val reader = BufferedReader(
                    InputStreamReader(
                        response.body!!.byteStream(),
                    )
                )
                var currentData = StringBuilder()
                var currentId: String? = null

                while (true) {
                    val line = reader.readLine() ?: break

                    // The SSE stream's own line-level log: what the transport
                    // actually receives, before any parsing. The on-device
                    // remote-engine debugging (the GDC round) needed this —
                    // the match ask arrived but the completion didn't, and
                    // there was no way to tell whether the SSE was alive,
                    // dead, or receiving events the parser was dropping.
                    // A `data:` line is NEVER logged as content: it carries
                    // the payload (credential metadata, presentations), and
                    // the logs must stay secret-free (the seedmark test
                    // enforces it) — its length and the JSON-RPC method are
                    // the whole diagnostic.
                    if (line.startsWith("data: ")) {
                        val payload = line.removePrefix("data: ")
                        val method = payload
                            .takeIf { it.startsWith("{") }
                            ?.let { body ->
                                body.indexOf("\"method\":\"")
                                    .takeIf { it >= 0 }
                                    ?.let { at ->
                                        body.substring(at + 10, body.indexOf('"', at + 10).coerceAtLeast(at + 10))
                                    }
                            }
                        Timber.d(
                            "SSE data: ${payload.length} chars" +
                                (method?.let { ", method=$it" } ?: "")
                        )
                    } else {
                        Timber.d("SSE line: ${if (line.length > 180) line.take(180) + "…" else line}")
                    }

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

    // The in-flight POST calls (#417): cancelled on transport failure so a
    // request hanging on a severed pooled connection cannot outlive the
    // transport that carried it.
    private val inFlightCalls =
        java.util.concurrent.ConcurrentHashMap.newKeySet<okhttp3.Call>()

    override suspend fun send(message: ByteArray) {
        val request = Request.Builder()
            .url(sendUrl)
            .apply { requestHeaders().forEach { (k, v) -> header(k, v) } }
            .post(message.toRequestBody("application/json".toMediaType()))
            .build()

        // Cancellable, off the caller's thread (#417): a flow.start POST
        // legitimately stays open for the flow's whole synchronous run (a
        // consent wait can hold it minutes), so a fixed short HTTP timeout
        // would kill live flows. But a POST sent on a SEVERED pooled
        // connection (the engine's machine restarted; the half-open TCP
        // socket accepts the write into the kernel buffer and never reads)
        // blocks the blocking-execute form FOREVER - the request hangs with
        // no error, no response, and the flow state spins until a full app
        // restart (found live on the realeyes demo: the v0.2.21 roll at
        // 23:53, the scan at 09:08 hung on the zombie connection; the
        // engine's #48 session-loss answers can never fire - the request
        // never reaches it). The async enqueue + invokeOnCancellation
        // (call.cancel) form makes the POST cancellable: the session's
        // request timeout (which wraps the send AND the await) cancels the
        // call, okhttp unblocks the socket immediately and evicts the dead
        // pooled connection, and the next attempt rides a fresh one.
        withContext(kotlinx.coroutines.Dispatchers.IO) {
            kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                val call = client.newCall(request)
                inFlightCalls.add(call)
                cont.invokeOnCancellation {
                    inFlightCalls.remove(call)
                    call.cancel()
                }
                call.enqueue(object : okhttp3.Callback {
                    override fun onResponse(call: okhttp3.Call, resp: okhttp3.Response) {
                        inFlightCalls.remove(call)
                        resp.use {
                            if (!it.isSuccessful) {
                                cont.resumeWithException(
                                    WmpSessionException("HTTP POST failed: ${it.code} ${it.message}")
                                )
                                return
                            }
                            // The binding is request/response OVER SSE: the
                            // POST's own HTTP response is empty (204 No
                            // Content); the JSON-RPC reply rides the SSE
                            // stream. Some deployments (proxies, an
                            // early-reply engine) answer the POST body
                            // directly - so deliver it to the incoming
                            // channel when there is one, never discarding a
                            // reply (found driving against a live engine:
                            // the session create answered, the transport
                            // threw it away, and every request timed out).
                            val body: ByteArray = it.body?.bytes() ?: ByteArray(0)
                            if (body.isNotEmpty()) {
                                incomingChannel.trySend(body)
                            }
                            cont.resume(Unit)
                        }
                    }

                    override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                        inFlightCalls.remove(call)
                        cont.resumeWithException(e)
                    }
                })
            }
        }
    }

    override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

    override suspend fun disconnect() {
        sseJob?.cancel()
        sseJob = null
        // A request hanging on a severed connection cannot outlive the
        // transport that carried it (#417).
        inFlightCalls.forEach { it.cancel() }
        inFlightCalls.clear()
        _state.value = TransportState.DISCONNECTED
    }

    companion object {
        private const val MAX_SEEN_EVENT_IDS = 4096

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS) // no read timeout for SSE
            .connectTimeout(30, TimeUnit.SECONDS)
            .build()

        /**
         * An OkHttpClient presenting the mTLS binding's certificate on
         * every request ([WmpSessionConfig.mtlsBinding]'s doc cites the
         * spec): the PEM pair becomes an in-memory PKCS12 key store the
         * SSLContext's key manager serves, so the TLS handshake answers
         * the server's CertificateRequest with the subscriber certificate
         * **and its issuing CA chain** — the deployment's load balancer
         * validates the leaf against its trust anchor, so the CA must ride
         * the chain (found live: presenting the leaf alone left the LB
         * unable to bind the session to the identity).
         *
         * The certificate PEM may carry the full chain (leaf first, then
         * the CA(s)); every certificate in it enters the key store entry.
         * The pair parses here, once, at client construction — a malformed
         * pair fails fast with the parse error, never as a mid-session
         * TLS refusal.
         */
        fun mtlsClient(binding: MtlsBinding): OkHttpClient {
            val certificates: List<java.security.cert.X509Certificate> =
                try {
                    java.security.cert.CertificateFactory
                        .getInstance("X.509")
                        .generateCertificates(binding.certificatePem.byteInputStream())
                        .filterIsInstance<java.security.cert.X509Certificate>()
                } catch (e: java.security.cert.CertificateException) {
                    emptyList()
                }
            if (certificates.isEmpty()) {
                throw IllegalArgumentException(
                    "the mtls binding's certificate PEM holds no certificate",
                )
            }
            val keyBytes = decodePemBody(binding.privateKeyPem, "PRIVATE KEY")
            val key = java.security.KeyFactory
                .getInstance("EC")
                .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(keyBytes))
            val store = java.security.KeyStore.getInstance("PKCS12")
            store.load(null, null)
            store.setKeyEntry(
                "mtls-binding",
                key,
                CharArray(0),
                certificates.toTypedArray(),
            )
            val kmf = javax.net.ssl.KeyManagerFactory
                .getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(store, CharArray(0))
            val sslContext = javax.net.ssl.SSLContext.getInstance("TLSv1.3")
            sslContext.init(kmf.keyManagers, null, null)
            return OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManagerForJvm())
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .connectTimeout(30, TimeUnit.SECONDS)
                .build()
        }

        /** The JVM's own trust anchors — the mTLS client still verifies the server. */
        private fun trustManagerForJvm(): javax.net.ssl.X509TrustManager {
            val factory = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm(),
            )
            factory.init(null as java.security.KeyStore?)
            return factory.trustManagers
                .filterIsInstance<javax.net.ssl.X509TrustManager>()
                .first()
        }

        /** The PEM body's base64, stripped of the armor and the labels. */
        private fun decodePemBody(pem: String, label: String): ByteArray {
            val body = Regex("-----BEGIN $label-----([\\s\\S]*?)-----END $label-----")
                .find(pem)?.groupValues?.get(1)
                ?: throw IllegalArgumentException("the PEM holds no $label block")
            val base64 = body.filter { !it.isWhitespace() }
            return java.util.Base64.getDecoder().decode(base64)
        }
    }
}
