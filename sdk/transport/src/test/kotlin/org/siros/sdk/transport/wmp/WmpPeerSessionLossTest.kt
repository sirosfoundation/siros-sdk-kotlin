package org.siros.sdk.transport.wmp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The session-loss self-heal (wallet-core#48): a flow start that names a
 * session the engine no longer honours - swept by a restart, or expired
 * while the wallet sat in the background - answers "Session not found"
 * (-31000) / "Session expired" (-31001) instead of running, and the peer
 * recreates the session and retries the start ONCE instead of surfacing
 * the refusal (the transport-disconnect recovery never fires when no
 * disconnect was observed - the wallet foregrounded straight into a scan).
 *
 * Driven with a scripted responder: a coroutine that watches the fake
 * transport's outgoing messages and answers each per the script, while the
 * flow under test runs on the runBlocking main path.
 */
class WmpPeerSessionLossTest {

    private val codec = WmpCodec()

    /** Waits until the transport has sent `count` messages. */
    private suspend fun waitForSentCount(transport: FakeTransport, count: Int) {
        var spins = 0
        while (transport.sentMessages.size < count) {
            if (spins++ > 500) throw AssertionError("timed out waiting for $count sent messages")
            delay(10)
        }
    }

    /** The request with the given 1-based sent index, decoded. */
    private fun request(transport: FakeTransport, index: Int): JsonRpcRequest {
        val req = codec.decodeRequest(transport.sentMessages[index - 1])
        assertTrue("the sent message carries a request id", req.id != null)
        return req
    }

    /** Answers the request with the given 1-based sent index with `response`. */
    private suspend fun respond(transport: FakeTransport, index: Int, response: (id: String) -> String) {
        transport.receiveFromServer(response(request(transport, index).id!!).toByteArray())
    }

    /** A successful session create response for `id`, session `sid`. */
    private fun createResponse(sid: String): (id: String) -> String = { id ->
        """{"jsonrpc":"2.0","id":"$id","result":{"wmp":{"session_id":"$sid","version":"0.1"},"resumption_token":"tok-$sid"}}"""
    }

    /** A successful flow start response for `id`. */
    private fun startResponse(): (id: String) -> String = { id ->
        """{"jsonrpc":"2.0","id":"$id","result":{"wmp":{"session_id":"s-any","version":"0.1"},"flow_id":"flow-1","flow_type":"oid4vp"}}"""
    }

    /** A `-31000` "Session not found" refusal for `id`, session `sid`. */
    private fun notFound(sid: String): (id: String) -> String = { id ->
        """{"jsonrpc":"2.0","id":"$id","error":{"code":-31000,"message":"Session not found","data":{"session_id":"$sid","capability":"flows"}}}"""
    }

    /** A `-31001` "Session expired" refusal for `id`, session `sid`. */
    private fun expired(sid: String): (id: String) -> String = { id ->
        """{"jsonrpc":"2.0","id":"$id","error":{"code":-31001,"message":"Session expired","data":{"session_id":"$sid","capability":"flows"}}}"""
    }

    /** A `-31005` capability refusal for `id` (not session loss). */
    private fun unsupported(): (id: String) -> String = { id ->
        """{"jsonrpc":"2.0","id":"$id","error":{"code":-31005,"message":"Capability not supported","data":{"capability":"flows"}}}"""
    }

    @Test
    fun startFlowRecreatesTheSessionAndRetriesOnSessionNotFound() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000))
        val peer = WmpPeer(session)

        // Script: create -> s-one; the start on s-one refuses -31000; the
        // recovery's fresh create -> s-two; the retried start succeeds.
        val responder = launch {
            waitForSentCount(transport, 1)
            respond(transport, 1, createResponse("s-one"))
            waitForSentCount(transport, 2)
            respond(transport, 2, notFound("s-one"))
            waitForSentCount(transport, 3)
            respond(transport, 3, createResponse("s-two"))
            waitForSentCount(transport, 4)
            respond(transport, 4, startResponse())
        }

        session.create("token")
        val result = peer.startFlow("oid4vp", "flow-1")

        assertEquals("flow-1", result.flowId)
        assertEquals("oid4vp", result.flowType)
        assertEquals("wmp.session.create", request(transport, 1).method)
        assertEquals("wmp.flow.start", request(transport, 2).method)
        assertTrue(
            "the first start names the dead session",
            transport.sentMessages[1].toString(Charsets.UTF_8).contains("s-one"),
        )
        // The recovery: a fresh create, then the retried start on it.
        assertEquals("wmp.session.create", request(transport, 3).method)
        assertEquals("wmp.flow.start", request(transport, 4).method)
        assertTrue(
            "the retried start names the fresh session",
            transport.sentMessages[3].toString(Charsets.UTF_8).contains("s-two"),
        )
        assertEquals(4, transport.sentMessages.size)
        responder.cancel()
    }

    @Test
    fun startFlowRecreatesTheSessionAndRetriesOnSessionExpired() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000))
        val peer = WmpPeer(session)

        // -31001: the record is present, its TTL passed. The original
        // recovery matched only "Session not found" and fell through to
        // FAILED here - the on-device #48 repro.
        val responder = launch {
            waitForSentCount(transport, 1)
            respond(transport, 1, createResponse("s-one"))
            waitForSentCount(transport, 2)
            respond(transport, 2, expired("s-one"))
            waitForSentCount(transport, 3)
            respond(transport, 3, createResponse("s-two"))
            waitForSentCount(transport, 4)
            respond(transport, 4, startResponse())
        }

        session.create("token")
        val result = peer.startFlow("oid4vp", "flow-1")

        assertEquals("flow-1", result.flowId)
        assertEquals(
            "the recovery's fresh create",
            "wmp.session.create",
            request(transport, 3).method,
        )
        assertEquals(4, transport.sentMessages.size)
        responder.cancel()
    }

    @Test
    fun startFlowSurfacesErrorsThatAreNotSessionLoss() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000))
        val peer = WmpPeer(session)

        val responder = launch {
            waitForSentCount(transport, 1)
            respond(transport, 1, createResponse("s-one"))
            waitForSentCount(transport, 2)
            // A refusal that is NOT session loss must surface, never retry.
            respond(transport, 2, unsupported())
        }

        session.create("token")
        try {
            peer.startFlow("oid4vp", "flow-1")
            throw AssertionError("Expected WmpSessionException")
        } catch (e: WmpSessionException) {
            assertTrue(
                "the refusal surfaces, not retried away",
                e.message!!.contains("Capability not supported"),
            )
        }
        // Exactly two messages: the create and the refused start - no
        // silent session recreation for an unrelated refusal.
        delay(200)
        assertEquals(2, transport.sentMessages.size)
        responder.cancel()
    }

    @Test
    fun startFlowRetriesOnceOnTransportTimeout() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(
            transport,
            config = WmpSessionConfig(requestTimeoutMs = 300, reconnectBaseMs = 1, reconnectMaxMs = 1),
        )
        val peer = WmpPeer(session)

        // Script: the create answers; the FIRST flow.start is never answered
        // (the severed connection); the RETRY (a fresh POST) answers.
        val responder = launch {
            waitForSentCount(transport, 1)
            respond(transport, 1, createResponse("s-one"))
            // The first start: recorded, deliberately never answered.
            waitForSentCount(transport, 2)
            // The retry after the timeout.
            waitForSentCount(transport, 3)
            respond(transport, 3, startResponse())
        }

        session.create("token")
        val result = peer.startFlow("oid4vp", "flow-1")

        assertEquals("flow-1", result.flowId)
        assertEquals(
            "the first start went out and hung",
            "wmp.flow.start",
            request(transport, 2).method,
        )
        assertEquals(
            "the retry is a fresh POST of the same flow",
            "wmp.flow.start",
            request(transport, 3).method,
        )
        assertEquals(3, transport.sentMessages.size)
        responder.cancel()
    }
}
