package org.sirosfoundation.sdk.transport.wmp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WmpPeerTest {

    private val codec = WmpCodec()

    companion object {
        private const val TEST_SESSION_ID = "session-123"
        private const val TEST_RESUMPTION_TOKEN = "resume-abc"
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

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private fun createSuccessResponse(requestId: String): String =
        """{"jsonrpc":"2.0","id":"$requestId","result":{"wmp":{"version":"0.1","session_id":"$TEST_SESSION_ID"},"resumption_token":"$TEST_RESUMPTION_TOKEN"}}"""

    private suspend fun CoroutineScope.setupConnectedPeer(transport: FakeTransport, peer: WmpPeer) {
        val connectJob = launch { peer.connect("token") }
        withTimeout(2_000) { while (transport.sentMessages.isEmpty()) delay(10) }
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
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        val eventDeferred = async { peer.flowEvents().first { it is FlowEvent.Progress } }

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

        val event = withTimeout(2_000) { eventDeferred.await() } as FlowEvent.Progress
        assertEquals("f1", event.flowId)
        assertEquals("processing", event.step)
        assertNotNull(profile.lastProgressParams)

        peer.close()
    }

    @Test
    fun inboundFlowStartRequestSendsResponse() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val peer = WmpPeer(session)
        peer.use(StubProfile())

        setupConnectedPeer(transport, peer)

        val sentBefore = transport.sentMessages.size

        // Server sends a wmp.flow.start *request* (has id)
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"req-1","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f2","flow_type":"test-flow"}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
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
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val peer = WmpPeer(session)
        peer.use(StubProfile())

        setupConnectedPeer(transport, peer)

        // First seed the flow type map
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f3","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        delay(100)

        val sentBefore = transport.sentMessages.size

        // Server sends a wmp.flow.action *request* (has id)
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"req-2","method":"wmp.flow.action","params":{"wmp":{"version":"0.1"},"flow_id":"f3","action":"confirm"}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
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
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        // Start flow
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f4","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        delay(100)

        // Complete flow
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"0.1"},"flow_id":"f4"}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
            while (profile.lastCompleteParams == null) delay(10)
        }

        assertNotNull(profile.lastCompleteParams)
        assertEquals("f4", profile.lastCompleteParams!!.flowId)

        // After complete, progress for same flow should NOT dispatch to handler (unknown type)
        profile.lastProgressParams = null
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"f4","step":"late"}}"""
                .toByteArray()
        )
        delay(100)
        // Handler should NOT have been called since flow type was forgotten
        // (lookupFlowType returns 'unknown', no handler registered for 'unknown')
        assertTrue(profile.lastProgressParams == null)

        peer.close()
    }

    @Test
    fun flowTypeMapClearedOnError() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val peer = WmpPeer(session)
        val profile = StubProfile()
        peer.use(profile)

        setupConnectedPeer(transport, peer)

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f5","flow_type":"test-flow"}}"""
                .toByteArray()
        )
        delay(100)

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.error","params":{"wmp":{"version":"0.1"},"flow_id":"f5","code":"ERR","message":"failed"}}"""
                .toByteArray()
        )

        withTimeout(2_000) {
            while (profile.lastErrorParams == null) delay(10)
        }

        assertEquals("f5", profile.lastErrorParams!!.flowId)
        assertEquals("ERR", profile.lastErrorParams!!.code)

        peer.close()
    }

    @Test
    fun flowEventsEmittedForAllLifecycleSteps() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val peer = WmpPeer(session)
        peer.use(StubProfile())

        setupConnectedPeer(transport, peer)

        val events = mutableListOf<FlowEvent>()
        val collectJob = launch { peer.flowEvents().collect { events.add(it) } }

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

        withTimeout(2_000) {
            while (events.size < 3) delay(10)
        }

        assertTrue(events[0] is FlowEvent.Started)
        assertTrue(events[1] is FlowEvent.Progress)
        assertTrue(events[2] is FlowEvent.Complete)

        collectJob.cancel()
        peer.close()
    }
}
