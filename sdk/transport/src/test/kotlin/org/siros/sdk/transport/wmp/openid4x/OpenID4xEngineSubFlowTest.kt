package org.siros.sdk.transport.wmp.openid4x

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.transport.wmp.FakeTransport
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpPeer
import org.siros.sdk.transport.wmp.WmpSession
import org.siros.sdk.transport.wmp.WmpSessionConfig

/**
 * The profile behind a real [WmpPeer] and a fake transport, driven by the frames the engine sends: a sign/match
 * sub-flow arrives as a `wmp.flow.start` REQUEST (go-wallet-backend feat/wmp-integration at b4f33e8,
 * internal/engine/wmphandler.go `startChildFlow` L2229-2243, a `peer.Call`), is acknowledged with the response the
 * engine waits for, and is answered later with `wmp.flow.complete` on the sub-flow's id.
 */
class OpenID4xEngineSubFlowTest {

    private val codec = WmpCodec()

    private fun CoroutineScope.connected(transport: FakeTransport, peer: WmpPeer) {
        val job = launch { peer.connect("token") }
        runBlocking {
            withTimeout(5_000) { while (transport.sentMessages.isEmpty()) delay(10) }
            val createReq = codec.decodeRequest(transport.sentMessages.last())
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"${createReq.id}","result":{"wmp":{"version":"0.1","session_id":"s1"},"resumption_token":"r"}}"""
                    .toByteArray(),
            )
            job.join()
        }
    }

    private suspend fun FakeTransport.awaitSent(predicate: (JsonObject) -> Boolean): JsonObject = withTimeout(5_000) {
        while (true) {
            sentMessages.map { Json.parseToJsonElement(String(it)).jsonObject }.firstOrNull(predicate)?.let { return@withTimeout it }
            delay(10)
        }
        @Suppress("UNREACHABLE_CODE") error("unreachable")
    }

    @Test
    fun anEngineSignSubFlowIsAcknowledgedThenAnsweredOnTheSubFlowId() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { flowId, _ ->
                    assertEquals("parent-1", flowId)
                    SignSubFlowResult(credentialCount = 2)
                },
            ),
        )
        peer.use(profile)
        connected(transport, peer)

        // wmphandler.go SendJSON *SignRequestMessage: wmp.flow.start, flow_type "sign", SignSubFlowParams with
        // parent_flow_id (L2372); a Call, so it has an id.
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"call-1","method":"wmp.flow.start","params":{"wmp":{"version":"0.1","session_id":"s1"},"flow_type":"sign","flow_id":"child-1","params":{"action":"decrypt_credential_response","nonce":"","audience":"","parent_flow_id":"parent-1","jwe":"a.b.c.d.e","deferred":false}}}"""
                .toByteArray(),
        )

        val ack = transport.awaitSent { it["id"] == JsonPrimitive("call-1") }
        val ackResult = ack["result"]!!.jsonObject
        assertEquals(JsonPrimitive("child-1"), ackResult["flow_id"])
        assertEquals(JsonPrimitive("sign"), ackResult["flow_type"])

        val complete = transport.awaitSent { it["method"] == JsonPrimitive("wmp.flow.complete") }
        val params = complete["params"]!!.jsonObject
        assertEquals(JsonPrimitive("child-1"), params["flow_id"])
        assertEquals(JsonPrimitive(2), params["result"]!!.jsonObject["credential_count"])
        assertTrue(
            "nothing is sent as a flow.action: that route needs a message_id the engine never gives the wallet",
            transport.sentMessages.none { String(it).contains("wmp.flow.action") },
        )
        peer.close()
    }

    @Test
    fun anEngineMatchSubFlowIsAnsweredOnTheSubFlowId() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onMatchRequest = { flowId, payload ->
                        assertEquals("parent-2", flowId)
                        assertTrue(payload!!.containsKey("dcql_query"))
                        MatchResult(matches = listOf(CredentialMatch(credentialId = "c1", credentialQueryId = "q")))
                    },
                ),
            ),
        )
        connected(transport, peer)

        // wmphandler.go SendJSON *MatchRequestMessage L2404-2425: flow_type "match", {dcql_query, parent_flow_id}.
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"call-2","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"match","flow_id":"child-2","params":{"dcql_query":{"credentials":[]},"parent_flow_id":"parent-2"}}}"""
                .toByteArray(),
        )

        transport.awaitSent { it["id"] == JsonPrimitive("call-2") }
        val complete = transport.awaitSent { it["method"] == JsonPrimitive("wmp.flow.complete") }
        val params = complete["params"]!!.jsonObject
        assertEquals(JsonPrimitive("child-2"), params["flow_id"])
        assertEquals(
            JsonPrimitive("c1"),
            params["result"]!!.jsonObject["matches"]!!.jsonArray.single().jsonObject["credential_id"],
        )
        peer.close()
    }

    @Test
    fun aFailedSubFlowReachesTheEngineAsAFlowErrorWithAnIntegerCode() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(OpenID4xProfile(OpenID4xConfig(onSignRequest = { _, _ -> throw SignRefusedException("no") })))
        connected(transport, peer)

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"call-3","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"sign","flow_id":"child-3","params":{"action":"sign_presentation","nonce":"n","audience":"a","parent_flow_id":"parent-3"}}}"""
                .toByteArray(),
        )

        val error = transport.awaitSent { it["method"] == JsonPrimitive("wmp.flow.error") }
        val params = error["params"]!!.jsonObject
        assertEquals(JsonPrimitive("child-3"), params["flow_id"])
        assertEquals(JsonPrimitive(-31006), params["code"])
        assertEquals(JsonPrimitive("rejected"), params["data"]!!.jsonObject["reason"])
        assertNull(params["result"])
        peer.close()
    }

    @Test
    fun aSubFlowTheWalletHasAnsweredIsNoLongerTracked() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        val progressed = java.util.concurrent.CopyOnWriteArrayList<String>()
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onSignRequest = { _, _ -> SignSubFlowResult(vpToken = "t") },
                    onProgress = { flowId, _, _ -> progressed.add(flowId) },
                ),
            ),
        )
        connected(transport, peer)
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"call-4","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"sign","flow_id":"child-4","params":{"action":"sign_presentation","nonce":"n","audience":"a","parent_flow_id":"parent-4"}}}"""
                .toByteArray(),
        )
        transport.awaitSent { it["method"] == JsonPrimitive("wmp.flow.complete") }

        // A frame for the answered sub-flow, then one for a flow that is still tracked (a parent the engine started).
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"child-4","step":"late"}}"""
                .toByteArray(),
        )
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"call-5","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"oid4vci","flow_id":"top-1"}}"""
                .toByteArray(),
        )
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"top-1","step":"parsing_offer"}}"""
                .toByteArray(),
        )
        withTimeout(5_000) { while ("top-1" !in progressed) delay(10) }

        assertTrue("the answered sub-flow's id was forgotten, so its late frame has no handler", "child-4" !in progressed)
        peer.close()
    }

    /** A transport whose sends can be made to fail, as a dropped connection does. */
    private class FlakyTransport(private val inner: FakeTransport) : org.siros.sdk.transport.Transport {
        @Volatile var failSends = false
        override val state get() = inner.state
        override suspend fun connect() = inner.connect()
        override suspend fun send(message: ByteArray) {
            if (failSends) throw java.io.IOException("connection lost")
            inner.send(message)
        }
        override fun incoming() = inner.incoming()
        override suspend fun disconnect() = inner.disconnect()
    }

    private fun signStartFrame(id: String, callId: String, parent: String) =
        """{"jsonrpc":"2.0","id":"$callId","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"sign","flow_id":"$id","params":{"action":"sign_presentation","nonce":"n","audience":"a","parent_flow_id":"$parent"}}}"""
            .toByteArray()

    @Test
    fun closingThePeerStopsTheSubFlowAnswersEvenWhenTellingTheServerFails() = runBlocking {
        val inner = FakeTransport()
        val transport = FlakyTransport(inner)
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        val gate = CompletableDeferred<Unit>()
        val entered = CompletableDeferred<Unit>()
        val stopped = CompletableDeferred<Unit>()
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onSignRequest = { _, _ ->
                        entered.complete(Unit)
                        try {
                            gate.await()
                            SignSubFlowResult(vpToken = "t")
                        } catch (e: CancellationException) {
                            stopped.complete(Unit)
                            throw e
                        }
                    },
                ),
            ),
        )
        connected(inner, peer)
        inner.receiveFromServer(signStartFrame("child-c", "call-c", "parent-c"))
        inner.awaitSent { it["id"] == JsonPrimitive("call-c") }
        // The acknowledgement does not say the callback has begun: close only once it is waiting.
        withTimeout(5_000) { entered.await() }

        transport.failSends = true
        val failure = runCatching { peer.close() }.exceptionOrNull()

        assertTrue("closing the session failed, as arranged", failure != null)
        withTimeout(5_000) { stopped.await() }
        Unit
    }

    @Test
    fun aSubFlowStartRepeatedAfterResumptionDoesNotRerunThePendingCallback() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        val gate = CompletableDeferred<Unit>()
        val calls = java.util.concurrent.atomic.AtomicInteger()
        val entered = CompletableDeferred<Unit>()
        peer.use(OpenID4xProfile(OpenID4xConfig(onSignRequest = { _, _ -> calls.incrementAndGet(); entered.complete(Unit); gate.await(); SignSubFlowResult(vpToken = "t") })))
        connected(transport, peer)

        transport.receiveFromServer(signStartFrame("child-d", "call-1", "parent-d"))
        transport.awaitSent { it["id"] == JsonPrimitive("call-1") }
        // The callback has begun (and is waiting) before the start is repeated: the count below then means "not run again".
        withTimeout(5_000) { entered.await() }
        // The engine reissues the same child id on the resumed session.
        transport.receiveFromServer(signStartFrame("child-d", "call-2", "parent-d"))
        transport.awaitSent { it["id"] == JsonPrimitive("call-2") }

        assertEquals("one callback for one request", 1, calls.get())
        gate.complete(Unit)
        transport.awaitSent { it["method"] == JsonPrimitive("wmp.flow.complete") }
        assertEquals(
            1,
            transport.sentMessages.count { String(it).contains("wmp.flow.complete") },
        )
        peer.close()
    }

    @Test
    fun cancellingAParentFlowLocallyStopsItsPendingSubFlow() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        val gate = CompletableDeferred<Unit>()
        val entered = CompletableDeferred<Unit>()
        val stopped = CompletableDeferred<Unit>()
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onSignRequest = { _, _ ->
                        entered.complete(Unit)
                        try {
                            gate.await()
                            SignSubFlowResult(vpToken = "t")
                        } catch (e: CancellationException) {
                            stopped.complete(Unit)
                            throw e
                        }
                    },
                ),
            ),
        )
        connected(transport, peer)
        // The parent flow, tracked as the engine started it.
        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"call-p","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"oid4vp","flow_id":"parent-e"}}""".toByteArray(),
        )
        transport.awaitSent { it["id"] == JsonPrimitive("call-p") }
        transport.receiveFromServer(signStartFrame("child-e", "call-e", "parent-e"))
        transport.awaitSent { it["id"] == JsonPrimitive("call-e") }
        // The acknowledgement does not say the callback has begun: cancel only once it is waiting.
        withTimeout(5_000) { entered.await() }

        peer.cancelFlow("parent-e", "user")

        withTimeout(5_000) { stopped.await() }
        gate.complete(Unit)
        delay(200)
        assertTrue(
            "the stopped sub-flow answers nothing",
            transport.sentMessages.none { String(it).contains("wmp.flow.complete") },
        )
        peer.close()
    }

    /** A transport whose sends can be held, keeping the peer's send lock taken meanwhile. */
    private class HoldableTransport(private val inner: FakeTransport) : org.siros.sdk.transport.Transport {
        @Volatile var hold: CompletableDeferred<Unit>? = null
        val holding = CompletableDeferred<Unit>()
        override val state get() = inner.state
        override suspend fun connect() = inner.connect()
        override suspend fun send(message: ByteArray) {
            hold?.let { holding.complete(Unit); it.await() }
            inner.send(message)
        }
        override fun incoming() = inner.incoming()
        override suspend fun disconnect() = inner.disconnect()
    }

    @Test
    fun aRefusedStartBehindAHeldSendNeverSendsAFlowFrameForAnEndedFlow() = runBlocking {
        val inner = FakeTransport()
        val transport = HoldableTransport(inner)
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        val progressed = java.util.concurrent.CopyOnWriteArrayList<String>()
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ -> CompletableDeferred<Unit>().await(); SignSubFlowResult() },
                onProgress = { flowId, _, _ -> progressed.add(flowId) },
            ),
        )
        profile.maxSubFlows = 1
        peer.use(profile)
        connected(inner, peer)
        // The table holds one pending sub-flow, so the next start is refused.
        inner.receiveFromServer(signStartFrame("child-1", "call-1", "parent-1"))
        inner.awaitSent { it["id"] == JsonPrimitive("call-1") }

        val gate = CompletableDeferred<Unit>()
        transport.hold = gate
        val held = launch { peer.notify("test.hold", null) } // takes the send lock and keeps it
        withTimeout(5_000) { transport.holding.await() }

        inner.receiveFromServer(signStartFrame("child-2", "call-2", "parent-2")) // refused; its error response queues behind the held send
        delay(200)
        profile.flowEnded("child-2")
        val cancelling = launch { peer.cancelFlow("parent-2", "user") } // its own notification queues behind the held send too
        profile.flowEnded("parent-2")
        gate.complete(Unit)
        held.join()
        cancelling.join()
        inner.awaitSent { it["id"] == JsonPrimitive("call-2") }

        val frames = inner.sentMessages.map { Json.parseToJsonElement(String(it)).jsonObject }
        val refusal = frames.single { it["id"] == JsonPrimitive("call-2") }
        assertEquals(JsonPrimitive("too many pending requests"), refusal["error"]!!.jsonObject["message"])
        assertTrue(
            "no flow.complete / flow.error is ever sent for the refused (and then ended) sub-flow: $frames",
            frames.none {
                (it["method"] == JsonPrimitive("wmp.flow.error") || it["method"] == JsonPrimitive("wmp.flow.complete")) &&
                    it["params"]?.jsonObject?.get("flow_id") == JsonPrimitive("child-2")
            },
        )
        // The refused flow is not tracked: a late frame for it has no handler, while one for the accepted sub-flow still does.
        inner.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"child-2","step":"late"}}""".toByteArray(),
        )
        inner.receiveFromServer(
            """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"child-1","step":"late"}}""".toByteArray(),
        )
        withTimeout(5_000) { while ("child-1" !in progressed) delay(10) }
        assertTrue("a refused start is forgotten by the peer", "child-2" !in progressed)
        peer.close()
    }

    @Test
    fun aParentThatEndsWithAPendingChildLeavesNoRoutingForTheChild() = runBlocking {
        for (ending in listOf("complete", "cancel")) {
            val transport = FakeTransport()
            val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
            val progressed = java.util.concurrent.CopyOnWriteArrayList<String>()
            val entered = CompletableDeferred<Unit>()
            peer.use(
                OpenID4xProfile(
                    OpenID4xConfig(
                        onSignRequest = { _, _ -> entered.complete(Unit); CompletableDeferred<Unit>().await(); SignSubFlowResult() },
                        onProgress = { flowId, _, _ -> progressed.add(flowId) },
                    ),
                ),
            )
            connected(transport, peer)
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"call-p","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"oid4vp","flow_id":"parent-$ending"}}""".toByteArray(),
            )
            transport.awaitSent { it["id"] == JsonPrimitive("call-p") }
            transport.receiveFromServer(signStartFrame("child-$ending", "call-c", "parent-$ending"))
            transport.awaitSent { it["id"] == JsonPrimitive("call-c") }
            withTimeout(5_000) { entered.await() }

            // The parent ends while its child is pending: the engine's terminal frame, or a local cancel.
            if (ending == "complete") {
                transport.receiveFromServer(
                    """{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"0.1"},"flow_id":"parent-$ending","result":{}}}""".toByteArray(),
                )
                withTimeout(5_000) { while (transport.sentMessages.isEmpty()) delay(10) }
                delay(300)
            } else {
                peer.cancelFlow("parent-$ending", "user")
            }
            // A late frame for the child has no handler; a frame for a flow that is still tracked does.
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"call-o","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"oid4vci","flow_id":"other-$ending"}}""".toByteArray(),
            )
            transport.awaitSent { it["id"] == JsonPrimitive("call-o") }
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"child-$ending","step":"late"}}""".toByteArray(),
            )
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"other-$ending","step":"s"}}""".toByteArray(),
            )
            withTimeout(5_000) { while ("other-$ending" !in progressed) delay(10) }
            assertTrue("$ending: the stopped child's routing was released: $progressed", "child-$ending" !in progressed)
            peer.close()
        }
    }
}
