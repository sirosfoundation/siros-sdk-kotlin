// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import kotlin.test.assertFailsWith
import org.junit.Test
import java.util.concurrent.CancellationException

/** Pure JVM election tests; Android radio behavior is deliberately left to instrumented/manual tests. */
class MdocBleTransportElectionTest {
    @Test
    fun startsEveryRoleAndClosesLoserBeforeReturningWinner() = runTest {
        val election = MdocBleTransportElection()
        val client = FakeCandidate("client")
        val server = FakeCandidate("server")
        election.start(listOf(client, server))

        assertEquals(1, client.startCalls)
        assertEquals(1, server.startCalls)
        election.candidateReady(client)
        election.candidateReady(server)

        val winner = election.await()
        assertSame(client, winner)
        assertSame(winner, election.await())
        assertEquals(0, client.closeCalls)
        assertEquals(1, server.closeCalls)
        election.close()
        assertEquals(1, client.closeCalls)
    }

    @Test
    fun establishmentIsSentOnlyOnElectedTransport() = runTest {
        val election = MdocBleTransportElection()
        val client = FakeCandidate("client")
        val server = FakeCandidate("server")
        election.start(listOf(client, server))
        election.candidateReady(server)
        election.candidateReady(client)
        val establishment = byteArrayOf(1, 2, 3)

        val winner = election.await()
        winner.send(establishment)

        assertEquals(0, client.sentMessages.size)
        assertEquals(listOf(establishment.toList()), server.sentMessages.map { it.toList() })
        assertEquals(1, client.closeCalls)
        assertEquals(0, server.closeCalls)
        election.close()
    }

    @Test
    fun oneRoleFailureDoesNotBeatAnotherReadyRole() = runTest {
        val election = MdocBleTransportElection()
        val client = FakeCandidate("client")
        val server = FakeCandidate("server")
        election.start(listOf(client, server))

        election.candidateFailed(client, IllegalStateException("scan failed"))
        election.candidateReady(server)

        assertSame(server, election.await())
        election.close()
    }

    @Test
    fun allRoleFailuresRejectAwait() = runTest {
        val election = MdocBleTransportElection()
        val client = FakeCandidate("client")
        val server = FakeCandidate("server")
        election.start(listOf(client, server))

        election.candidateFailed(client, IllegalStateException("scan failed"))
        election.candidateFailed(server, IllegalStateException("advertise failed"))

        val error = assertFailsWith<MdocBleTransportException> { election.await() }
        assertTrue(error.message.orEmpty().contains("scan failed"))
        assertTrue(error.message.orEmpty().contains("advertise failed"))
        election.close()
    }

    @Test
    fun closeIsIdempotentAndClosesPendingCandidates() = runTest {
        val election = MdocBleTransportElection()
        val candidate = FakeCandidate("client")
        election.start(listOf(candidate))

        election.close()
        election.close()

        assertEquals(1, candidate.closeCalls)
        assertFailsWith<CancellationException> { election.await() }
    }

    @Test
    fun cancellingAwaitClosesAllCandidates() = runTest {
        val election = MdocBleTransportElection()
        val client = FakeCandidate("client")
        val server = FakeCandidate("server")
        election.start(listOf(client, server))
        val waiting = launch(start = CoroutineStart.UNDISPATCHED) { election.await() }

        waiting.cancelAndJoin()

        assertTrue(waiting.isCancelled)
        assertEquals(1, client.closeCalls)
        assertEquals(1, server.closeCalls)
    }

    private class FakeCandidate(override val role: String) : MdocBleCandidate {
        val sentMessages = mutableListOf<ByteArray>()
        var startCalls = 0
        var closeCalls = 0

        override fun start() {
            startCalls++
        }

        override suspend fun send(message: ByteArray) {
            sentMessages += message.copyOf()
        }

        override suspend fun receive(): ByteArray = byteArrayOf()

        override suspend fun close() {
            closeCalls++
        }
    }
}
