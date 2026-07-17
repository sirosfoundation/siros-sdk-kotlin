package org.sirosfoundation.sdk.transport.wmp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WmpPeerTest {

    private val codec = WmpCodec()

    companion object {
        private const val TEST_SESSION_ID = "session-123"
        private const val TEST_RESUMPTION_TOKEN = "resume-abc"
        private const val TEST_TIMEOUT_MS = 5_000L
    }

    // ---------------------------------------------------------------------------
    // Minimal stub profile
    // ---------------------------------------------------------------------------

    private class StubProfile(
        override val name: String = "stub",
        override val capabilities: List<String> = emptyList(),
        val handledFlowTypes: List<String> = listOf("test-flow"),
    ) : WmpProfile, WmpFlowHandler {
        override val flowTypes get() = handledFlowTypes

        var lastStartParams: FlowStartParams? = null
        var lastActionParams: FlowActionParams? = null
        var lastProgressParams: FlowProgressParams? = null
        var lastCompleteParams: FlowCompleteParams? = null
        var lastErrorParams: FlowErrorParams? = null
        var lastCancelParams: FlowCancelParams? = null

        override fun init(ctx: WmpPeerContext) {}

        override suspend fun startFlow(params: FlowStartParams): FlowStartResult {
            lastStartParams = params
            return FlowStartResult(flowId = params.flowId, flowType = params.flowType)
        }

        override suspend fun handleAction(params: FlowActionParams): FlowActionResult {
            lastActionParams = params
            return FlowActionResult(flowId = params.flowId)
        }

        override suspend fun handleProgress(params: FlowProgressParams) { lastProgressParams = params }
        override suspend fun handleComplete(params: FlowCompleteParams) { lastCompleteParams = params }
        override suspend fun handleError(params: FlowErrorParams) { lastErrorParams = params }
        override suspend fun handleCancel(params: FlowCancelParams) { lastCancelParams = params }
    }

    private class StubResolveProfile(
        override val resolveTypes: List<String> = listOf("did"),
    ) : WmpProfile, WmpResolveHandler {
        override val name: String = "stub-resolve"
        override val capabilities: List<String> = emptyList()

        var lastResolveParams: ResolveParams? = null

        override fun init(ctx: WmpPeerContext) {}

        override suspend fun handleResolve(params: ResolveParams): ResolveResult {
            lastResolveParams = params
            return ResolveResult(type = params.type)
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private fun createSuccessResponse(requestId: String): String =
        """{"jsonrpc":"2.0","id":"$requestId","result":{"wmp":{"version":"0.1","session_id":"$TEST_SESSION_ID"},"resumption_token":"$TEST_RESUMPTION_TOKEN"}}"""

    private suspend fun CoroutineScope.setupConnectedPeer(transport: FakeTransport, peer: WmpPeer) {
        val connectJob = launch { peer.connect("token") }
        withTimeout(TEST_TIMEOUT_MS) { while (transport.sentMessages.isEmpty()) delay(10) }
        val createReq = codec.decodeRequest(transport.sentMessages.last())
        transport.receiveFromServer(createSuccessResponse(createReq.id!!).toByteArray())
        connectJob.join()
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    @Test
    fun inboundFlowProgressDispatchesToHandlerAndEmitsEvent() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        val eventDeferred = async { peer.flowEvents().first { it is FlowEvent.Progress } }
        yield() // Let the async coroutine subscribe to the SharedFlow before sending

        // Server sends a progress notification for a known flow; first seed the flow type map
        // by sending a flow.start first so the flow type is known
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f1","flow_type":"test-flow"}}"""
                .toByteArray()
        )

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"f1","step":"processing"}}"""
                .toByteArray()
        )

        val event = withTimeout(TEST_TIMEOUT_MS) { eventDeferred.await() } as FlowEvent.Progress
        assertEquals("f1", event.flowId)
        assertEquals("processing", event.step)
        assertNotNull(profile.lastProgressParams)

        peer.close()
    }

    @Test
    fun inboundFlowStartRequestSendsResponse() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        peer.use(StubProfile())

        setupConnectedPeer(transport, peer)

        val sentBefore = transport.sentMessages.size

        // Server sends a wmp.flow.start *request* (has id)
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"req-1","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f2","flow_type":"test-flow"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (transport.sentMessages.size <= sentBefore) delay(10)
        }

        // The last sent message should be a JSON-RPC response with id "req-1"
        val responseMsg = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue("Expected JSON-RPC response with id", responseMsg.contains("\"id\":\"req-1\""))
        assertTrue("Expected result field", responseMsg.contains("\"result\""))

        peer.close()
    }

    @Test
    fun inboundFlowActionRequestSendsResponse() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        // First seed the flow type map
        val stubProfile = StubProfile()
        peer.use(stubProfile)

        setupConnectedPeer(transport, peer)

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f3","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        withTimeout(TEST_TIMEOUT_MS) { while (stubProfile.lastStartParams == null) delay(10) }

        val sentBefore = transport.sentMessages.size

        // Server sends a wmp.flow.action *request* (has id)
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"req-2","method":"wmp.flow.action","params":{"wmp":{"version":"0.1"},"flow_id":"f3","action":"confirm"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (transport.sentMessages.size <= sentBefore) delay(10)
        }

        val responseMsg = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue("Expected JSON-RPC response with id", responseMsg.contains("\"id\":\"req-2\""))
        assertTrue("Expected result field", responseMsg.contains("\"result\""))

        peer.close()
    }

    @Test
    fun flowTypeMapClearedOnComplete() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        // Start flow
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f4","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        withTimeout(TEST_TIMEOUT_MS) { while (profile.lastStartParams == null) delay(10) }

        // Complete flow
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"0.1"},"flow_id":"f4"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (profile.lastCompleteParams == null) delay(10)
        }

        assertNotNull(profile.lastCompleteParams)
        assertEquals("f4", profile.lastCompleteParams!!.flowId)

        // After complete, progress for same flow should NOT dispatch to handler (unknown type).
        // Subscribe to flowEvents to confirm dispatch completed without calling the handler.
        profile.lastProgressParams = null
        val progressEventDeferred = async {
            peer.flowEvents().first { it is FlowEvent.Progress && (it as FlowEvent.Progress).flowId == "f4" }
        }
        yield() // Let the async coroutine subscribe before sending
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"f4","step":"late"}}"""
                .toByteArray()
        )
        withTimeout(TEST_TIMEOUT_MS) { progressEventDeferred.await() }
        // Handler should NOT have been called since flow type was forgotten
        // (lookupFlowType returns 'unknown', no handler registered for 'unknown')
        assertNull(profile.lastProgressParams)

        peer.close()
    }

    @Test
    fun flowTypeMapClearedOnError() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f5","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        withTimeout(TEST_TIMEOUT_MS) { while (profile.lastStartParams == null) delay(10) }

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.error","params":{"wmp":{"version":"0.1"},"flow_id":"f5","code":"ERR","message":"failed"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (profile.lastErrorParams == null) delay(10)
        }

        assertEquals("f5", profile.lastErrorParams!!.flowId)
        assertEquals("ERR", profile.lastErrorParams!!.code)

        peer.close()
    }

    @Test
    fun flowEventsEmittedForAllLifecycleSteps() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        peer.use(StubProfile())

        setupConnectedPeer(transport, peer)

        val events = mutableListOf<FlowEvent>()
        val collectJob = launch { peer.flowEvents().collect { events.add(it) } }
        yield() // Let the launch coroutine subscribe before sending

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f6","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"f6","step":"step1"}}"""
                .toByteArray()
        )
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"0.1"},"flow_id":"f6"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (events.size < 3) delay(10)
        }

        assertTrue(events[0] is FlowEvent.Started)
        assertTrue(events[1] is FlowEvent.Progress)
        assertTrue(events[2] is FlowEvent.Complete)

        collectJob.cancel()
        peer.close()
    }

    @Test
    fun clientInitiatedStartFlowTracksFlowTypeForSubsequentProgress() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        // Client initiates the flow (outgoing request); server responds with success
        val startJob = launch { peer.startFlow("test-flow", "fc1") }
        withTimeout(TEST_TIMEOUT_MS) {
            // Wait for the flow.start request to be sent
            while (transport.sentMessages.size < 2) delay(10)
        }
        val flowStartReq = codec.decodeRequest(transport.sentMessages.last())
        // Server acknowledges the flow start
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"${flowStartReq.id}","result":{"flow_id":"fc1","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        startJob.join()

        // Server now sends progress for the client-initiated flow
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"fc1","step":"processing"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) { while (profile.lastProgressParams == null) delay(10) }

        assertNotNull("Handler should be called for client-initiated flow", profile.lastProgressParams)
        assertEquals("fc1", profile.lastProgressParams!!.flowId)

        peer.close()
    }

    @Test
    fun clientCancelFlowCleansUpFlowTypeTracking() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        // Seed the flow type map via a server-initiated flow.start
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"fc2","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        withTimeout(TEST_TIMEOUT_MS) { while (profile.lastStartParams == null) delay(10) }

        // Client cancels the flow; flow type should be removed from tracking
        peer.cancelFlow("fc2", "user cancelled")

        // Progress after cancel should NOT dispatch to handler (flow type was forgotten).
        // Subscribe to flowEvents first so we can wait for the dispatch to complete.
        profile.lastProgressParams = null
        val progressEventDeferred = async {
            peer.flowEvents().first { it is FlowEvent.Progress && (it as FlowEvent.Progress).flowId == "fc2" }
        }
        yield() // Let the async coroutine subscribe before sending
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"fc2","step":"late"}}"""
                .toByteArray()
        )
        withTimeout(TEST_TIMEOUT_MS) { progressEventDeferred.await() }

        assertNull("Flow handler should not receive progress after client cancel", profile.lastProgressParams)
        peer.close()
    }

    @Test
    fun inboundFlowStartUnknownTypeRespondsWithError() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        // No profile registered for "unknown-flow"
        peer.use(StubProfile(handledFlowTypes = listOf("test-flow")))

        setupConnectedPeer(transport, peer)

        val sentBefore = transport.sentMessages.size

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"err-1","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"unknown-flow-id","flow_type":"unknown-flow"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (transport.sentMessages.size <= sentBefore) delay(10)
        }

        val responseMsg = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue("Expected error response for unregistered flow type", responseMsg.contains("\"error\""))
        assertTrue("Expected request id in error response", responseMsg.contains("\"id\":\"err-1\""))

        peer.close()
    }

    @Test
    fun inboundResolveRequestDispatchesToResolveHandler() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        val resolveProfile = StubResolveProfile()
        peer.use(resolveProfile)

        setupConnectedPeer(transport, peer)

        val sentBefore = transport.sentMessages.size

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"res-1","method":"wmp.resolve","params":{"type":"did","identifier":"did:example:123"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (transport.sentMessages.size <= sentBefore) delay(10)
        }

        assertNotNull("Resolve handler should have been called", resolveProfile.lastResolveParams)
        assertEquals("did", resolveProfile.lastResolveParams!!.type)
        assertEquals("did:example:123", resolveProfile.lastResolveParams!!.identifier)

        val responseMsg = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue("Expected JSON-RPC response with id", responseMsg.contains("\"id\":\"res-1\""))
        assertTrue("Expected result field", responseMsg.contains("\"result\""))
        assertFalse("Should not contain error", responseMsg.contains("\"error\""))

        peer.close()
    }

    @Test
    fun inboundResolveRequestUnknownTypeRespondsWithError() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = TEST_TIMEOUT_MS))
        val peer = WmpPeer(session)
        peer.use(StubResolveProfile(resolveTypes = listOf("did")))

        setupConnectedPeer(transport, peer)

        val sentBefore = transport.sentMessages.size

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"res-2","method":"wmp.resolve","params":{"type":"unknown","identifier":"foo"}}"""
                .toByteArray()
        )

        withTimeout(TEST_TIMEOUT_MS) {
            while (transport.sentMessages.size <= sentBefore) delay(10)
        }

        val responseMsg = transport.sentMessages.last().toString(Charsets.UTF_8)
        assertTrue("Expected error response for unsupported resolve type", responseMsg.contains("\"error\""))
        assertTrue("Expected request id", responseMsg.contains("\"id\":\"res-2\""))

        peer.close()
    }
}
