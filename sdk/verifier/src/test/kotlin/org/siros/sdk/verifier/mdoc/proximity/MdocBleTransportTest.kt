// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import kotlin.test.assertFailsWith
import org.junit.Test

/** JVM tests of the radio-independent base transport; no Android Bluetooth APIs are loaded. */
class MdocBleTransportTest {
    @Test
    fun receiveReturnsOnlyReassembledWholeMessages() = runTest {
        val transport = FakeTransport().apply { start() }

        transport.acceptChunk(byteArrayOf(0x01, 1, 2))
        transport.acceptChunk(byteArrayOf(0x00, 3))

        assertArrayEquals(byteArrayOf(1, 2, 3), transport.receive())
        transport.close()
    }

    @Test
    fun sendsAreSerializedWithoutInterleavingChunks() = runTest {
        val transport = FakeTransport().apply { start() }

        val first = launch(start = CoroutineStart.UNDISPATCHED) { transport.send(byteArrayOf(1, 1, 1)) }
        val second = launch { transport.send(byteArrayOf(2, 2, 2)) }
        joinAll(first, second)

        val payload = transport.sentChunks.flatMap { chunk -> chunk.drop(1).map { it.toInt() } }
        assertEquals(listOf(1, 1, 1, 2, 2, 2), payload)
        transport.close()
    }

    @Test
    fun malformedInputFailsSessionInsteadOfCrashingCallback() = runTest {
        val transport = FakeTransport().apply { start() }

        transport.acceptChunk(ByteArray(0))

        assertFailsWith<MdocBleTransportException> { transport.receive() }
        assertEquals(1, transport.closeRadioCalls)
        transport.close()
        assertEquals(1, transport.closeRadioCalls)
    }

    @Test
    fun disconnectRejectsReceiveAndCloseIsDeterministic() = runTest {
        val transport = FakeTransport().apply { start() }

        transport.disconnect()
        val error = assertFailsWith<MdocBleTransportException> { transport.receive() }

        assertTrue(error.message.orEmpty().contains("disconnected"))
        transport.close()
        transport.close()
        assertEquals(1, transport.closeRadioCalls)
        assertFailsWith<MdocBleTransportException> { transport.send(byteArrayOf(1)) }
    }

    @Test
    fun receiveTimeoutFailsAndClosesSession() = runTest {
        val transport = FakeTransport(ioTimeoutMs = 25).apply { start() }

        val error = assertFailsWith<MdocBleTransportException> { transport.receive() }

        assertTrue(error.message.orEmpty().contains("timed out"))
        assertEquals(1, transport.closeRadioCalls)
    }

    @Test
    fun cancellingBlockedReceiveClosesSessionOnce() = runTest {
        val transport = FakeTransport().apply { start() }
        val waiting = launch(start = CoroutineStart.UNDISPATCHED) { transport.receive() }

        waiting.cancelAndJoin()
        transport.close()

        assertTrue(waiting.isCancelled)
        assertEquals(1, transport.closeRadioCalls)
    }

    private class FakeTransport(
        ioTimeoutMs: Long = 5_000,
    ) : AbstractMdocBleTransport(
        role = "fake",
        onReady = {},
        onFailure = { _, _ -> },
        readyTimeoutMs = 5_000,
        ioTimeoutMs = ioTimeoutMs,
    ) {
        val sentChunks = mutableListOf<ByteArray>()
        var closeRadioCalls = 0

        override fun startRadio() = Unit

        override fun closeRadio() {
            closeRadioCalls++
        }

        override fun currentMaxChunkSize(): Int = 3

        override suspend fun sendChunk(chunk: ByteArray) {
            delay(1)
            sentChunks += chunk
        }

        fun acceptChunk(chunk: ByteArray) = onIncomingChunk(chunk)

        fun disconnect() = fail("disconnected")
    }
}
