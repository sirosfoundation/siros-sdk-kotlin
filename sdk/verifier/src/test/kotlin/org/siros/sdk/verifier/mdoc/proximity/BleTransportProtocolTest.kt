// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import kotlin.test.assertFailsWith
import org.junit.Test

/** Pure JVM protocol tests. Real radio interoperability still requires instrumented/manual testing. */
class BleTransportProtocolTest {
    @Test
    fun chunkingHonoursWireLimitAndReassemblyPreservesWholeMessages() {
        val first = ByteArray(517) { (it % 251).toByte() }
        val second = byteArrayOf(9, 8, 7)
        val reassembler = MdocBleReassembler()

        val chunks = MdocBleProtocol.chunk(first, maxChunkSize = 20)
        assertTrue(chunks.all { it.size <= 20 })
        assertEquals(0x01.toByte(), chunks.first()[0])
        assertEquals(0x00.toByte(), chunks.last()[0])
        var actual: ByteArray? = null
        for (chunk in chunks) {
            val complete = reassembler.feed(chunk)
            if (chunk !== chunks.last()) assertNull(complete)
            actual = complete ?: actual
        }
        assertArrayEquals(first, actual)

        var secondActual: ByteArray? = null
        for (chunk in MdocBleProtocol.chunk(second, maxChunkSize = 2)) {
            secondActual = reassembler.feed(chunk) ?: secondActual
        }
        assertArrayEquals(second, secondActual)
    }

    @Test
    fun reassemblerAcceptsExactlyTwoMiB() {
        val message = ByteArray(MdocBleProtocol.MAX_MESSAGE_SIZE) { (it % 31).toByte() }
        val reassembler = MdocBleReassembler()
        var actual: ByteArray? = null

        for (chunk in MdocBleProtocol.chunk(message, maxChunkSize = 512)) {
            actual = reassembler.feed(chunk) ?: actual
        }

        assertArrayEquals(message, actual)
    }

    @Test
    fun oversizedChunkAbortsAndResetsReassembly() {
        val reassembler = MdocBleReassembler()
        val oversized = byteArrayOf(0x01) + ByteArray(MdocBleProtocol.MAX_MESSAGE_SIZE + 1)

        assertFailsWith<IllegalStateException> { reassembler.feed(oversized) }

        assertArrayEquals(byteArrayOf(4, 5), reassembler.feed(byteArrayOf(0x00, 4, 5)))
    }

    @Test
    fun malformedChunkAbortsPartialMessageAndResetsReassembly() {
        val reassembler = MdocBleReassembler()
        assertNull(reassembler.feed(byteArrayOf(0x01, 9)))

        assertFailsWith<IllegalArgumentException> { reassembler.feed(ByteArray(0)) }
        assertArrayEquals(byteArrayOf(4), reassembler.feed(byteArrayOf(0x00, 4)))
        assertFailsWith<IllegalArgumentException> { reassembler.feed(byteArrayOf(0x02, 1)) }
    }

    @Test
    fun clientWaitsForNotificationsAndStateStartAcknowledgement() {
        val handshake = MdocBleClientHandshake()
        assertFalse(handshake.ready)

        handshake.onNotifications(MdocBleNotificationCharacteristic.STATE, true)
        handshake.onStateStartWritten()
        assertFalse(handshake.ready)

        handshake.onNotifications(MdocBleNotificationCharacteristic.SERVER_TO_CLIENT, true)
        assertTrue(handshake.ready)

        handshake.onNotifications(MdocBleNotificationCharacteristic.SERVER_TO_CLIENT, false)
        assertFalse(handshake.ready)
    }

    @Test
    fun serverWaitsForSubscriptionEvenWhenStartArrivesFirst() {
        val handshake = MdocBleServerHandshake()
        assertEquals(MdocBleStateEvent.START, handshake.onState(byteArrayOf(0x01)))
        assertTrue(handshake.started)
        assertFalse(handshake.ready)

        handshake.onServer2ClientNotifications(true)
        assertTrue(handshake.ready)
        handshake.onServer2ClientNotifications(false)
        assertFalse(handshake.ready)
    }

    @Test
    fun stateParserRejectsMalformedAndUnknownValues() {
        assertEquals(MdocBleStateEvent.END, MdocBleState.parse(byteArrayOf(0x02)))
        assertFailsWith<IllegalArgumentException> { MdocBleState.parse(ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { MdocBleState.parse(byteArrayOf(0x01, 0x00)) }
        assertFailsWith<IllegalArgumentException> { MdocBleState.parse(byteArrayOf(0x7f)) }
    }

    @Test
    fun identMatchesIndependentRfc5869Vector() {
        // Same independently cross-checked vector as ProximitySessionCryptoTest:
        // HKDF-SHA256 with no salt uses a 32-byte all-zero HMAC key.
        val ident = MdocBleProtocol.computeIdent(ByteArray(88) { it.toByte() })
        assertArrayEquals(hex("0cd459a9fa6e6f91cba134e5e8c3c3ee"), ident)
    }

    @Test
    fun mtuChunkSizeIsFlooredAndAttributeCapped() {
        assertEquals(20, MdocBleProtocol.maxChunkSize(1))
        assertEquals(20, MdocBleProtocol.maxChunkSize(23))
        assertEquals(512, MdocBleProtocol.maxChunkSize(517))
        assertEquals(100, MdocBleProtocol.maxChunkSize(103))
    }

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
