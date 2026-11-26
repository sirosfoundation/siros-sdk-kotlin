package org.siros.sdk.transport.wmp

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WmpSessionTest {

    private val codec = WmpCodec()

    @Test
    fun createSendsSessionCreateAndTransitionsActive() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        val createJob = launch {
            session.create(authToken = "app-token", sender = "sample-wallet")
        }

        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        assertEquals("wmp.session.create", createReq.method)
        assertNotNull(createReq.id)
        val createText = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue(createText.contains("\"type\":\"bearer\""))
        assertTrue(createText.contains("\"token\":\"app-token\""))

        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        session.close()
    }

    /**
     * The mTLS binding gate ([WmpSessionConfig.mtlsBinding], wmp-core
     * §4.4.6: the `ebcore` scheme authenticates with `mtls`): the session
     * create sends `auth.type = "mtls"` — the certificate the transport
     * presents at TLS is the credential, so no token rides the params.
     * The bearer default is the first test's assertion.
     */
    @Test
    fun mtlsBindingFlipsTheCreateAuthType() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(
                mtlsBinding = MtlsBinding(
                    certificatePem = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
                    privateKeyPem = "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n",
                ),
            ),
        )

        val createJob = launch {
            session.create(authToken = "app-token", sender = "sample-wallet")
        }

        waitForSentCount(transport, 1)
        val createText = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue(createText.contains("\"type\":\"mtls\""))
        assertTrue("no bearer rides an mTLS create", !createText.contains("app-token"))
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        session.close()
    }

    @Test
    fun sendRequestTimesOutWithoutResponse() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 100),
        )

        try {
            session.sendRequest("wmp.flow.action", null)
            throw AssertionError("Expected WmpTimeoutException")
        } catch (_: WmpTimeoutException) {
        }
    }

    @Test
    fun notificationsFlowEmitsServerNotification() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(requestTimeoutMs = 2_000),
        )

        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        val notificationDeferred = async { session.notifications().first() }
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"state":"processing"}}"""
                .toByteArray()
        )

        val notification = notificationDeferred.await()
        assertEquals("wmp.flow.progress", notification.method)

        session.close()
    }

    @Test
    fun disconnectTriggersResumeAndReturnsActive() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(
                requestTimeoutMs = 2_000,
                maxReconnectAttempts = 2,
                reconnectBaseMs = 1,
                reconnectMaxMs = 5,
            ),
        )

        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()
        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        transport.simulateDisconnect()

        waitForRequestMethod(transport, "wmp.session.resume")
        val resumeReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"${resumeReq.id}","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumed":true}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
            while (session.state.value != WmpSessionState.ACTIVE) {
                delay(10)
            }
        }

        session.close()
    }

    @Test
    fun failedReconnectAttemptsTransitionToFailed() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(
                requestTimeoutMs = 1_000,
                maxReconnectAttempts = 2,
                reconnectBaseMs = 1,
                reconnectMaxMs = 5,
            ),
        )

        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        transport.simulateFailure()

        repeat(2) {
            waitForRequestMethod(transport, "wmp.session.resume")
            val resumeReq = codec.decodeRequest(transport.sentMessages.last())
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"${resumeReq.id}","error":{"code":-31001,"message":"resume failed"}}"""
                    .toByteArray()
            )
        }

        withTimeout(3_000) {
            while (session.state.value != WmpSessionState.FAILED) {
                delay(10)
            }
        }

        assertEquals(WmpSessionState.FAILED, session.state.value)
    }

    @Test
    fun aTransportFailureIsHandledEvenWhenTheSessionIsNotActive() = runBlocking {
        // #447's third leg: the collector's historic ACTIVE-only guard
        // silently dropped the transport's FAILED whenever the session sat
        // in RESUMING, CONNECTING or FAILED — the stranded-forever case
        // (the stream's liveness deadline fired mid-resume and no path
        // retried; the wallet sat on a dead stream until a force-stop).
        // The failure must be handled whatever the session's own state is:
        // the recovery is token-guarded and single-flight.
        val transport = FakeTransport()
        val session = WmpSession(
            transport,
            config = WmpSessionConfig(
                requestTimeoutMs = 1_000,
                maxReconnectAttempts = 2,
                reconnectBaseMs = 1,
                reconnectMaxMs = 5,
            ),
        )

        // Create → ACTIVE, with a resumption token.
        val createJob = launch { session.create("token") }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()
        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        // A resume that FAILS: the session lands FAILED — not ACTIVE. This
        // is the state the historic guard dropped the disconnect in.
        val resumeJob = launch {
            try {
                session.resume()
            } catch (ignored: Exception) {
            }
        }
        waitForSentCount(transport, 2)
        val resumeReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"${resumeReq.id}","error":{"code":-31001,"message":"resume failed"}}"""
                .toByteArray()
        )
        resumeJob.join()
        assertEquals(WmpSessionState.FAILED, session.state.value)

        // NOW the transport fails while the session is FAILED (not
        // ACTIVE) — the keepalive's verdict on a silent stream (#447).
        transport.simulateFailure()

        // The collector handles it instead of dropping it: a resume
        // attempt appears, and answered, the session is ACTIVE again.
        waitForSentCount(transport, 3)
        val recoveryReq = codec.decodeRequest(transport.sentMessages.last())
        assertEquals("wmp.session.resume", recoveryReq.method)
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"${recoveryReq.id}","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumed":true}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
            while (session.state.value != WmpSessionState.ACTIVE) {
                delay(10)
            }
        }
        assertEquals(WmpSessionState.ACTIVE, session.state.value)
    }

    private suspend fun waitForSentCount(transport: FakeTransport, expected: Int) {
        withTimeout(2_000) {
            while (transport.sentMessages.size < expected) {
                delay(10)
            }
        }
    }

    private suspend fun waitForRequestMethod(transport: FakeTransport, method: String) {
        withTimeout(2_000) {
            while (true) {
                val matches = transport.sentMessages
                    .map { codec.decodeRequest(it) }
                    .any { it.method == method }
                if (matches) return@withTimeout
                delay(10)
            }
        }

        assertTrue(
            transport.sentMessages
                .map { codec.decodeRequest(it) }
                .any { it.method == method }
        )
    }

    private fun createSuccessResponse(requestId: String): String {
        return """{"jsonrpc":"2.0","id":"$requestId","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumption_token":"resume-abc"}}"""
    }

    /**
     * wmp-core §4.4: `ttl` is OPTIONAL — omitted, the ENGINE's default
     * applies. The SDK naming a short explicit ttl reaped live join
     * sessions at one hour against engines defaulting to days (found live:
     * golden-fox, 2026-11-25), so the default is to not name one.
     */
    @Test
    fun createOmitsTheTtlByDefault_TheEnginesOwnDefaultApplies() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport = transport, config = WmpSessionConfig())

        val createJob = launch { session.create(authToken = "tok") }
        waitForSentCount(transport, 1)
        val text = transport.sentMessages.last().toString(Charsets.UTF_8)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        assertFalse("an omitted ttl must not ride as an explicit null", text.contains("\"ttl\""))
        session.close()
    }

    @Test
    fun createNamesTheTtlWhenConfigured() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(sessionTtlSeconds = 120),
        )

        val createJob = launch { session.create(authToken = "tok") }
        waitForSentCount(transport, 1)
        val text = transport.sentMessages.last().toString(Charsets.UTF_8)
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()

        assertTrue(text.contains("\"ttl\":120"))
        session.close()
    }

    @Test
    fun createOffersCapabilitiesOnlyWhenGiven() = runBlocking {
        suspend fun sentCreate(offered: kotlinx.serialization.json.JsonObject?): String {
            val transport = FakeTransport()
            val session = WmpSession(transport = transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
            val job = launch { session.create("tok", capabilitiesOffered = offered) }
            waitForSentCount(transport, 1)
            val req = codec.decodeRequest(transport.sentMessages.last())
            val text = transport.sentMessages.last().toString(Charsets.UTF_8)
            transport.receiveFromServer(createSuccessResponse(req.id!!).toByteArray())
            job.join()
            session.close()
            return text
        }

        val withCaps = sentCreate(
            kotlinx.serialization.json.buildJsonObject {
                put(
                    "transaction_data",
                    kotlinx.serialization.json.buildJsonObject {
                        put("versions", kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive(1))))
                    },
                )
            },
        )
        val without = sentCreate(null)

        assertTrue(withCaps, withCaps.contains("\"capabilities_offered\":{\"transaction_data\":{\"versions\":[1]}}"))
        assertTrue(without, !without.contains("transaction_data"))
    }

    /** A transport whose first send waits on [release], simulating an in-flight POST. */
    private class HoldingTransport(private val release: kotlinx.coroutines.CompletableDeferred<Unit>) : org.siros.sdk.transport.Transport {
        val sent = java.util.concurrent.CopyOnWriteArrayList<String>()
        val holding = kotlinx.coroutines.CompletableDeferred<Unit>()
        override val state = kotlinx.coroutines.flow.MutableStateFlow(org.siros.sdk.transport.TransportState.CONNECTED)
        override suspend fun connect() {}
        override suspend fun send(message: ByteArray) {
            if (sent.isEmpty()) {
                holding.complete(Unit)
                release.await()
            }
            sent.add(String(message))
        }
        override fun incoming() = kotlinx.coroutines.flow.emptyFlow<ByteArray>()
        override suspend fun disconnect() {}
    }

    @Test
    fun aNotificationIsSkippedWhenNotWantedAndItsCheckIsAtSendTime() = runBlocking {
        val release = kotlinx.coroutines.CompletableDeferred<Unit>()
        val transport = HoldingTransport(release)
        val session = WmpSession(transport)
        val first = launch { session.sendNotification("test.first", null) }
        withTimeout(5_000) { transport.holding.await() }

        // The send mutex is gone (the drive-found deadlock): the wanted
        // check happens once, at send time, and a send does not queue
        // behind another in-flight send.
        val wanted = java.util.concurrent.atomic.AtomicBoolean(false)
        assertEquals("not sent: not wanted at send time", false, withTimeout(5_000) { session.sendNotificationIf("test.skipped", null) { wanted.get() } })

        // A check that passes can be stale by the time the POST lands —
        // accepted (the receiver re-checks; the profile ignores answers
        // for ended sub-flows).
        wanted.set(true)
        val stale = async { session.sendNotificationIf("test.second", null) { wanted.get() } }
        delay(100) // the second POST is in flight
        wanted.set(false)
        release.complete(Unit)
        first.join()
        assertEquals("sent: the check passed at send time; the in-flight flip is the receiver's to re-check", true, withTimeout(5_000) { stale.await() })

        assertTrue("the skipped notification never went out", transport.sent.none { it.contains("test.skipped") })
        assertTrue("the stale-checked notification went out", transport.sent.any { it.contains("test.second") })
        // A send that is wanted goes out too.
        assertEquals(true, session.sendNotificationIf("test.third", null) { true })
        assertEquals(3, transport.sent.size)
    }

    @Test
    fun expiredSessionFallsBackToFreshCreate() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport = transport,
            config = WmpSessionConfig(
                requestTimeoutMs = 1_000,
                maxReconnectAttempts = 2,
                reconnectBaseMs = 1,
                reconnectMaxMs = 5,
            ),
        )

        // Create: the first session.
        val createJob = launch { session.create("token", sender = "wallet", capabilitiesOffered = null) }
        waitForSentCount(transport, 1)
        val createReq = codec.decodeRequest(transport.sentMessages[0])
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        createJob.join()
        assertEquals(WmpSessionState.ACTIVE, session.state.value)

        // The SSE drops; the resume loop starts.
        transport.simulateFailure()

        // Both resume attempts fail with "Session not found" (the session
        // expired server-side, the engine's in-memory store dropped it).
        repeat(2) {
            waitForSentCount(transport, transport.sentMessages.size + 1)
            val resumeReq = codec.decodeRequest(transport.sentMessages.last())
            assertTrue(resumeReq.method == "wmp.session.resume")
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"${resumeReq.id}","error":{"code":-31000,"message":"Session not found"}}"""
                    .toByteArray()
            )
        }

        // After the resume exhaustion, the fresh-create fallback fires:
        // a NEW wmp.session.create (not another resume), with the same
        // auth token.
        waitForSentCount(transport, transport.sentMessages.size + 1)
        val freshReq = codec.decodeRequest(transport.sentMessages.last())
        assertTrue("the fallback is a fresh create, not another resume",
            freshReq.method == "wmp.session.create")
        transport.receiveFromServer(createSuccessResponse(freshReq.id!!).toByteArray())

        withTimeout(3_000) {
            while (session.state.value != WmpSessionState.ACTIVE) {
                delay(10)
            }
        }
        assertEquals(WmpSessionState.ACTIVE, session.state.value)
    }
}
