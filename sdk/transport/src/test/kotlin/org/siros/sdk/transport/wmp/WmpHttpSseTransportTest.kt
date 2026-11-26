package org.siros.sdk.transport.wmp

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.transport.TransportState
import timber.log.Timber

/** The SSE binding's guarantees for a flow that delivers a secret: connected before anything is sent, no event twice, nothing logged — and the liveness the stream owes its reader (#447). */
class WmpHttpSseTransportTest {

    private val requests = mutableListOf<Request>()
    private var release: CountDownLatch? = null

    /** A client whose event stream answers with [body] (one frame per call of [bodies]), after [release] if set. */
    private fun client(vararg bodies: String): OkHttpClient {
        var call = 0
        return OkHttpClient.Builder().addInterceptor { chain ->
            requests += chain.request()
            release?.await(10, TimeUnit.SECONDS)
            val text = bodies[minOf(call++, bodies.size - 1)]
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(
                    object : ResponseBody() {
                        override fun contentType() = null
                        override fun contentLength() = -1L
                        override fun source() = Buffer().write(text.toByteArray())
                    },
                ).build()
        }.build()
    }

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            logs += message + (t?.let { " " + it.toString() + it.message } ?: "")
        }
    }

    @Before fun plant() = Timber.plant(tree)

    @After fun uproot() = Timber.uproot(tree)

    @Test
    fun connectReturnsOnlyOnceTheStreamIsOpen() = runBlocking {
        release = CountDownLatch(1)
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("data: {}\n\n"))
        val connected = CompletableDeferred<Unit>()
        val job = launch(Dispatchers.Default) {
            // The stream opens with the session id (the engine's SSE route requires it).
            transport.onSessionCreated("s1")
            connected.complete(Unit)
        }
        delay(300)
        assertFalse("connect() must not return before the stream is open", connected.isCompleted)
        assertEquals(TransportState.CONNECTING, transport.state.value)
        release!!.countDown()
        withTimeout(5_000) { connected.await() }
        job.join()
        assertTrue(transport.state.value == TransportState.CONNECTED || transport.state.value == TransportState.DISCONNECTED)
    }

    @Test
    fun aFailedConnectionReturnsFailedInsteadOfHanging() = runBlocking {
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(503).message("no")
                .body(ResponseBody.create(null, "")).build()
        }.build()
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", http)
        withTimeout(5_000) { transport.onSessionCreated("s1") }
        assertEquals(TransportState.FAILED, transport.state.value)
    }

    @Test
    fun theBearerIsFreshenedPerRequestNotBakedInAtConnect() = runBlocking {
        // The binding is stateless - the engine validates EVERY POST - and AS
        // tokens live ~2 minutes, so a token fixed at connect dies with its
        // expiry and every later POST is answered "Not authorized" (found
        // driving an issuance 40 minutes after login).
        var minted = 0
        val transport = WmpHttpSseTransport(
            sendUrl = "https://x.test/send",
            sseUrl = "https://x.test/events",
            client = client("data: {}\n\n", "data: {}\n\n", "data: {}\n\n"),
            tokenProvider = { "token-${minted++}" },
        )
        transport.onSessionCreated("s1")
        transport.send("{\"a\":1}".toByteArray())
        transport.send("{\"a\":2}".toByteArray())
        transport.disconnect()

        val auths = requests.map { it.header("Authorization") }
        assertTrue("every request carries a fresh bearer", auths.size >= 3)
        // The provider answered PER REQUEST: the SSE stream's connect and each POST re-asked it.
        assertEquals(auths.size, minted)
        auths.take(3).forEachIndexed { i, auth ->
            assertEquals("Bearer token-$i", auth)
        }
    }

    @Test
    fun aNullTokenFallsBackToNoAuthorizationHeaderAndExtraHeadersApply() = runBlocking {
        val transport = WmpHttpSseTransport(
            sendUrl = "https://x.test/send",
            sseUrl = "https://x.test/events",
            client = client("data: {}\n\n"),
            extraHeaders = mapOf("X-Tenant" to "default"),
            tokenProvider = { null },
        )
        transport.onSessionCreated("s1")
        transport.send("{}".toByteArray())
        transport.disconnect()
        assertTrue("a null provider answer means no Authorization header", requests.all { it.header("Authorization") == null })
        assertTrue(requests.all { it.header("X-Tenant") == "default" })
    }

    @Test
    fun aReplayedEventIdIsDeliveredOnce() = runBlocking {
        val body = "id: 1\ndata: {\"n\":1}\n\nid: 2\ndata: {\"n\":2}\n\nid: 1\ndata: {\"n\":1}\n\nid: 3\ndata: {\"n\":3}\n\n"
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client(body))
        transport.onSessionCreated("s1")
        val received = withTimeout(5_000) { transport.incoming().take(3).toList() }.map { it.toString(Charsets.UTF_8) }
        assertEquals(listOf("{\"n\":1}", "{\"n\":2}", "{\"n\":3}"), received)
    }

    @Test
    fun eventsWithoutAnIdAreAllDelivered() = runBlocking {
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("data: a\n\ndata: a\n\n"))
        transport.onSessionCreated("s1")
        assertEquals(listOf("a", "a"), withTimeout(5_000) { transport.incoming().take(2).toList() }.map { it.toString(Charsets.UTF_8) })
    }

    @Test
    fun aReconnectAsksForEventsAfterTheLastOneReceived_andDoesNotRedeliverReplays() = runBlocking {
        val transport = WmpHttpSseTransport(
            "https://x.test/send", "https://x.test/events",
            client("id: 1\ndata: a\n\nid: 2\ndata: b\n\n", "id: 2\ndata: b\n\nid: 3\ndata: c\n\n"),
        )
        transport.onSessionCreated("s1")
        assertNull(requests[0].header("Last-Event-ID"))
        val first = withTimeout(5_000) { transport.incoming().take(2).toList() }
        assertEquals(listOf("a", "b"), first.map { it.toString(Charsets.UTF_8) })
        // The first stream ended; connect again.
        withTimeout(5_000) { while (transport.state.value != TransportState.DISCONNECTED) delay(10) }
        transport.connect()
        assertEquals("2", requests[1].header("Last-Event-ID"))
        // "b" is replayed on the new stream and not delivered again.
        assertEquals(listOf("c"), withTimeout(5_000) { transport.incoming().take(1).toList() }.map { it.toString(Charsets.UTF_8) })
    }

    @Test
    fun theStreamIsNamedWithTheSessionIdTheEngineRoutesBy() = runBlocking {
        // The engine's SSE route requires `?session_id=` and routes the replay
        // and the live events by it; the stream cannot open before the create
        // answered (a pre-create connect defers to onSessionCreated).
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("data: {}\n\n"))
        withTimeout(5_000) { transport.connect() }
        assertTrue("a pre-create connect opens nothing", requests.isEmpty())
        withTimeout(5_000) { transport.onSessionCreated("ses-1") }
        assertTrue(requests.isNotEmpty())
        assertEquals("ses-1", requests.last().url.queryParameter("session_id"))
    }

    @Test
    fun aRecreateRetargetsTheLiveStreamToTheFreshSession() = runBlocking {
        // The re-scan path (WmpSession.recreate → create → onSessionCreated with a
        // NEW id while the first stream is still open): the engine routes every
        // event by `?session_id=`, so a stream left on the retired id never sees
        // the new session's outbox pushes. Found live: a second scan of a
        // re-minted invite left the wallet deaf to its group — heartbeats flowed,
        // zero data lines, the inbox never filled.
        val transport = WmpHttpSseTransport(
            "https://x.test/send", "https://x.test/events",
            client("id: 1\ndata: first\n\n", "id: 2\ndata: second\n\n"),
        )
        withTimeout(5_000) { transport.onSessionCreated("ses-1") }
        assertEquals("the first stream rides the first session", "ses-1", requests.last().url.queryParameter("session_id"))
        // The re-create answers a fresh session id.
        withTimeout(5_000) { transport.onSessionCreated("ses-2") }
        assertEquals(
            "the re-create moves the stream to the fresh session (the retired stream is replaced, not kept)",
            "ses-2",
            requests.last().url.queryParameter("session_id"),
        )
        // Both streams deliver (the channel carries the first stream's event too).
        val seen = withTimeout(5_000) { transport.incoming().take(2).toList() }
        assertEquals(listOf("first", "second"), seen.map { it.toString(Charsets.UTF_8) })
    }

    /** An SSE body whose [emit] runs per read — the test's lever on what the stream delivers, byte for byte. */
    private fun body(emit: (sink: Buffer, byteCount: Long) -> Long): ResponseBody =
        object : ResponseBody() {
            override fun contentType() = null
            override fun contentLength() = -1L
            override fun source(): okio.BufferedSource =
                (
                    object : okio.Source {
                        override fun read(sink: Buffer, byteCount: Long): Long = emit(sink, byteCount)
                        override fun close() {}
                        override fun timeout(): okio.Timeout = okio.Timeout.NONE
                    }
                ).buffer()
        }

    @Test
    fun aStreamSilentPastTheDeadlineFailsTheTransport() = runBlocking {
        // #447's half-open socket: the stream dies silently (a carrier NAT
        // idle timeout, Android doze, a proxy that dropped the TCP session
        // without RST) — the kernel still shows the connection established,
        // the state stays CONNECTED, and no socket error ever surfaces.
        // The keepalive must catch it: the engine heartbeats every ~15s
        // (wmp-transport.md §4.3.4), so the deadline — no received LINE,
        // heartbeat or data, for the whole window — means the stream is
        // dead, and the transport marks itself FAILED so the session's
        // recovery reconnects and replays from Last-Event-ID.
        val unblock = CountDownLatch(1)
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            requests += chain.request()
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(
                    body { _, _ ->
                        // The half-open socket: the read blocks with no byte
                        // arriving and no error delivered — until the test
                        // lets go.
                        unblock.await(20, TimeUnit.SECONDS)
                        -1L
                    },
                )
                .build()
        }.build()
        val transport = WmpHttpSseTransport(
            "https://x.test/send", "https://x.test/events", http,
            keepaliveCheckMs = 50, keepaliveFailAfterMs = 250,
        )
        withTimeout(5_000) { transport.onSessionCreated("s1") }
        try {
            assertEquals(TransportState.CONNECTED, transport.state.value)

            withTimeout(5_000) { while (transport.state.value != TransportState.FAILED) delay(10) }
            assertEquals(TransportState.FAILED, transport.state.value)
        } finally {
            // Never leak the blocked read, whatever the assertions said.
            unblock.countDown()
        }
    }

    @Test
    fun aStreamThatKeepsReceivingHeartbeatsIsNotFailed() = runBlocking {
        // The keepalive's other half: liveness is measured by RECEIVED
        // LINES, not by the clock alone. The engine's heartbeat comments
        // count as activity (wmp-transport.md §4.3.4), so a stream whose
        // data is idle but whose heartbeats arrive never trips the
        // deadline — the check may not fail a live stream. The body beats
        // until the test releases it: the stream may not go silent on its
        // own before the assertion.
        val unblock = CountDownLatch(1)
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            requests += chain.request()
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(
                    body { sink, _ ->
                        if (unblock.await(60, TimeUnit.MILLISECONDS)) {
                            -1L
                        } else {
                            // a heartbeat every ~60ms — well inside the deadline
                            sink.writeUtf8(": heartbeat\n\n")
                            ": heartbeat\n\n".length.toLong()
                        }
                    },
                )
                .build()
        }.build()
        val transport = WmpHttpSseTransport(
            "https://x.test/send", "https://x.test/events", http,
            keepaliveCheckMs = 100, keepaliveFailAfterMs = 1_000,
        )
        withTimeout(5_000) { transport.onSessionCreated("s1") }
        try {
            // ~25 heartbeats over 1.5s — the deadline that fails a dead
            // stream is a full second of silence: a live one survives every
            // check with an eightfold margin.
            delay(1_500)
            assertEquals(TransportState.CONNECTED, transport.state.value)
        } finally {
            // Never leak the beating stream, whatever the assertion said.
            transport.disconnect()
            unblock.countDown()
        }
    }

    @Test
    fun noEventDataAndNoDecodeErrorIsLogged() = runBlocking {
        val secret = "SEEDMARK-00112233445566778899aabbccddeeff"
        val transport = WmpHttpSseTransport("https://x.test/send", "https://x.test/events", client("id: 1\ndata: {\"credential_metadata\":\"$secret\"}\n\n"))
        transport.onSessionCreated("s1")
        withTimeout(5_000) { transport.incoming().take(1).toList() }
        logs.forEach { assertFalse(it, it.contains("SEEDMARK")) }

        // A frame the session cannot decode: the error is logged without quoting the frame.
        val fake = FakeTransport()
        val session = WmpSession(transport = fake, config = WmpSessionConfig(requestTimeoutMs = 2_000))
        val job = launch { session.create("tok") }
        withTimeout(2_000) { while (fake.sentMessages.isEmpty()) delay(10) }
        val req = WmpCodec().decodeRequest(fake.sentMessages.last())
        fake.receiveFromServer("""{"jsonrpc":"2.0","id":"${req.id}","result":{"wmp":{"version":"0.1","session_id":"s"},"resumption_token":"r"}}""".toByteArray())
        job.join()
        fake.receiveFromServer("""{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"result":{"credential_metadata":{"org.siros.secret_seed":{"ns":"$secret"}}} BROKEN""".toByteArray())
        delay(300)
        assertTrue("the decode failure was logged", logs.any { it.contains("Error handling incoming WMP message") })
        logs.forEach { assertFalse(it, it.contains("SEEDMARK")) }
        session.close()
    }
}
