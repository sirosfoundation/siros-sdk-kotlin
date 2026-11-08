// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import org.siros.sdk.transport.Transport
import org.siros.sdk.transport.TransportState
import timber.log.Timber
import uniffi.engine_adapter_sdk.EngineConfig
import uniffi.engine_adapter_sdk.Host
import uniffi.engine_adapter_sdk.HttpClient
import uniffi.engine_adapter_sdk.Pdp
import uniffi.engine_adapter_sdk.WmpEngine
import uniffi.engine_adapter_sdk.createEngine

/**
 * The SDK's [Transport] over the in-process Rust engine core — the local
 * mode of the engine switch (docs/engine-switching.md's deployment
 * table): the WMP engine runs in the wallet's own process, loaded from
 * the `org.siros:siros-wallet-core` AAR, and this class is the transport
 * the existing `WmpSession`/`WmpPeer`/profile stack plugs into in place
 * of [WmpWebSocketTransport].
 *
 * Everything downstream works unchanged: the profile dispatch, the flow
 * events, the `FlowClient`. The engine's outgoing fetches go through
 * [http] (OkHttp or the app's stack — native TLS, system roots, VPNs),
 * the wallet's own asks (the sub-flows: signing, consent, the key
 * custody) through [host], and the trust evaluation through [pdp] —
 * `null` fails closed at the trust step, exactly as the remote engine
 * does with an unconfigured PDP.
 *
 * The UniFFI Kotlin bindings are vendored source
 * (`uniffi/engine_adapter_sdk`), regenerated per engine release; the
 * native `.so` libraries ride the AAR.
 *
 * @param http The engine's HTTP port: every fetch the engine makes.
 * @param host The wallet host: the engine's sub-flow asks.
 * @param pdp The trust port (the app's trust stack), or null to fail
 * closed at the trust step.
 * @param config The engine's construction configuration; the defaults
 * fit a wallet (1 MiB messages, a 3600 s session TTL, 16 concurrent
 * flows, the consent check in warn mode).
 */
class WmpUniFFITransport(
    private val http: HttpClient,
    private val host: Host,
    private val pdp: Pdp? = null,
    private val config: EngineConfig = EngineConfig(
        maxMessageSize = 1048576uL,
        defaultSessionTtlSecs = 3600uL,
        maxConcurrentFlows = 16uL,
        consentCheck = "warn",
    ),
) : Transport {

    private val engine: WmpEngine = createEngine(config, http, host, pdp)

    private val _state = MutableStateFlow(TransportState.DISCONNECTED)
    override val state: StateFlow<TransportState> = _state

    private val incomingChannel = Channel<ByteArray>(Channel.BUFFERED)

    init {
        Timber.d("WmpUniFFITransport: in-process engine created")
    }

    override suspend fun connect() {
        if (_state.value == TransportState.CONNECTED) return
        _state.value = TransportState.CONNECTING
        // The in-process engine is always "connected" — no socket to open.
        _state.value = TransportState.CONNECTED
    }

    override suspend fun send(message: ByteArray) {
        // One WMP message in, the reply out; a notification answers null.
        // The call blocks until the engine answers: call it from a worker
        // the engine's sub-flow asks ([host]) are free to run on.
        val response = engine.send(message)
        if (response != null) {
            incomingChannel.trySend(response)
        }
        // Deliver any queued notifications (flow progress, sub-flow
        // starts, completions) that arrived while the request was in
        // flight — the transport's polling counterpart of the SSE
        // stream the remote mode reads.
        for (n in engine.takeNotifications()) {
            incomingChannel.trySend(n)
        }
    }

    override fun incoming(): Flow<ByteArray> = incomingChannel.receiveAsFlow()

    override suspend fun disconnect() {
        _state.value = TransportState.DISCONNECTED
        incomingChannel.close()
        Timber.d("WmpUniFFITransport: disconnected")
    }
}