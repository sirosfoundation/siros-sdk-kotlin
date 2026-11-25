package org.siros.sdk.transport.wmp

import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private suspend fun waitForSentCount(transport: FakeTransport, count: Int) {
    repeat(200) {
        if (transport.sentMessages.size >= count) return
        delay(10)
    }
    error("expected $count sent messages, saw ${transport.sentMessages.size}")
}

/** A persisted session restores by id + token after an app restart. */
class WmpSessionResumeWithTest {
    @Test
    fun resumeWithSeedsThePersistedSessionAndRotatesTheToken() = runBlocking {
        val transport = FakeTransport()
        val session = WmpSession(transport)

        val job = launch { session.resumeWith("session-123", "resume-abc") }
        waitForSentCount(transport, 1)
        val text = transport.sentMessages.last().toString(Charsets.UTF_8)
        val req = WmpCodec().decodeRequest(transport.sentMessages.last())
        assertEquals("wmp.session.resume", req.method)
        assertTrue(text.contains("session-123"))
        assertTrue(text.contains("resume-abc"))

        transport.receiveFromServer(
            """{"jsonrpc":"2.0","id":"${req.id}","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumed":true,"resumption_token":"resume-rotated"}}"""
                .toByteArray(),
        )
        job.join()

        assertEquals("session-123", session.currentSessionId)
        assertEquals("resume-rotated", session.currentResumptionToken)
    }
}
