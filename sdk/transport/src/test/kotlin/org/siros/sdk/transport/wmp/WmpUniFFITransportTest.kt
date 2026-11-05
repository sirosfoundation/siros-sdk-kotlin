// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.first
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.siros.sdk.transport.TransportState
import uniffi.engine_adapter_sdk.Host
import uniffi.engine_adapter_sdk.HttpClient
import uniffi.engine_adapter_sdk.HttpRequest
import uniffi.engine_adapter_sdk.HttpResponse
import uniffi.engine_adapter_sdk.SdkException

/**
 * The in-process transport's tests. The engine's native library rides the
 * AAR (`org.siros:siros-wallet-core`), so on the JVM these run only where
 * the library loads — [assumeEngineLoadable] skips them otherwise (the
 * plain-gradle CI has no native library; wire the AAR to run them).
 *
 * Where the library loads, the tests drive the real loop: a WMP session
 * create through the engine, the reply and the engine's notifications
 * through `incoming()`, the transport's state machine.
 */
class WmpUniFFITransportTest {

    /** Whether the engine's native library loads on this JVM. */
    private fun engineLoadable(): Boolean = try {
        val engine = uniffi.engine_adapter_sdk.createEngine(
            uniffi.engine_adapter_sdk.EngineConfig(
                maxMessageSize = 1048576uL,
                defaultSessionTtlSecs = 3600uL,
                maxConcurrentFlows = 16uL,
                consentCheck = "warn",
            ),
            RefusingHttp,
            RefusingHost,
            null,
        )
        engine.isReady()
        true
    } catch (_: Throwable) {
        // UnsatisfiedLinkError without the native library; any other
        // failure is the same verdict for this probe.
        false
    }

    @Test
    fun connectTransitionsToConnected() = runBlocking {
        assumeTrue(engineLoadable())
        val transport = WmpUniFFITransport(RefusingHttp, RefusingHost)

        assertEquals(TransportState.DISCONNECTED, transport.state.value)
        transport.connect()
        assertEquals(TransportState.CONNECTED, transport.state.value)
    }

    @Test
    fun sendDeliversTheReplyThroughIncoming() = runBlocking {
        assumeTrue(engineLoadable())
        val transport = WmpUniFFITransport(RefusingHttp, RefusingHost)
        transport.connect()

        // One WMP request: the session create. The reply comes back
        // through incoming(), as the WmpSession delivers it.
        val create = """{"jsonrpc":"2.0","id":"uniffi-1",""" +
            """"method":"wmp.session.create",""" +
            """"params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}"""
        transport.send(create.toByteArray())

        val reply = withTimeout(10_000) { transport.incoming().first() }
        val text = String(reply)
        assertTrue("the reply carries the request id: $text", text.contains("\"id\":\"uniffi-1\""))
        assertTrue("the session was assigned: $text", text.contains("ses-"))
        assertTrue("the capabilities are present: $text", text.contains("\"capabilities\""))
    }

    @Test
    fun disconnectTransitionsBack() = runBlocking {
        assumeTrue(engineLoadable())
        val transport = WmpUniFFITransport(RefusingHttp, RefusingHost)
        transport.connect()

        transport.disconnect()

        assertEquals(TransportState.DISCONNECTED, transport.state.value)
    }

    /** The HTTP port that refuses everything: these tests make no fetch. */
    private object RefusingHttp : HttpClient {
        override suspend fun send(request: HttpRequest): HttpResponse =
            throw SdkException.NetworkRefused()
    }

    /** The host that declines every ask: these tests ask for nothing. */
    private object RefusingHost : Host {
        override suspend fun requestSign(
            params: uniffi.engine_adapter_sdk.SignParams,
        ): uniffi.engine_adapter_sdk.SignResult = throw SdkException.Declined()

        override suspend fun requestMatch(
            params: uniffi.engine_adapter_sdk.MatchParams,
        ): uniffi.engine_adapter_sdk.MatchResult = throw SdkException.Declined()

        override suspend fun requestVp(
            params: uniffi.engine_adapter_sdk.VpParams,
        ): uniffi.engine_adapter_sdk.VpResult = throw SdkException.Declined()

        override suspend fun requestDpopProof(
            params: uniffi.engine_adapter_sdk.DpopProofParams,
        ): uniffi.engine_adapter_sdk.DpopProofResult = throw SdkException.Declined()

        override suspend fun requestConsent(
            params: uniffi.engine_adapter_sdk.ConsentParams,
        ): uniffi.engine_adapter_sdk.ConsentResult = throw SdkException.Declined()

        override suspend fun requestTxCode(flowId: String): String = ""

        override suspend fun openAuthorization(flowId: String, url: String) {}

        override suspend fun requestSigningKey(
            params: uniffi.engine_adapter_sdk.SigningKeyParams,
        ): uniffi.engine_adapter_sdk.SigningKeyResult = throw SdkException.Cannot("no key")

        override suspend fun requestAttestation(
            params: uniffi.engine_adapter_sdk.AttestationParams,
        ): uniffi.engine_adapter_sdk.AttestationResult = throw SdkException.Cannot("no attestation")

        override suspend fun requestCredentialSelection(
            params: uniffi.engine_adapter_sdk.CredentialSelectionParams,
        ): uniffi.engine_adapter_sdk.CredentialSelectionResult =
            throw SdkException.Cannot("no selection")

        override fun progress(flowId: String, step: String, detail: String?) {}
    }
}