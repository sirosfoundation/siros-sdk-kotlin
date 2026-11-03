// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef.android

import java.io.IOException
import java.util.ArrayDeque
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.verifier.mdoc.proximity.ndef.MdocNfcHandoverParser

class NdefType4ProtocolTest {

    @Test
    fun selectAndReadCommands_useType4AidFileAndBigEndianOffsets() {
        assertArrayEquals(hex("00a4040007d276000085010100"), NdefType4Protocol.selectNdefApplication())
        assertArrayEquals(hex("00a4000c02e104"), NdefType4Protocol.selectNdefFile())
        assertArrayEquals(hex("00b0000002"), NdefType4Protocol.readNlen())
        assertArrayEquals(hex("00b00102fe"), NdefType4Protocol.readBinary(offset = 0x0102, length = 0xFE))
    }

    @Test
    fun readNdef_returnsExactBytesAndUsesOnlyBoundedReads() {
        val ndef = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val exchange = Exchange(
            SUCCESS,
            SUCCESS,
            hex("00049000"),
            hex("010203049000"),
        )

        val result = NdefType4Protocol.readNdef(transceive = exchange::transceive)

        assertArrayEquals(ndef, result)
        assertEquals(
            listOf(
                NdefType4Protocol.selectNdefApplication().toList(),
                NdefType4Protocol.selectNdefFile().toList(),
                NdefType4Protocol.readNlen().toList(),
                NdefType4Protocol.readBinary(offset = 2, length = 4).toList(),
            ),
            exchange.commands.map(ByteArray::toList),
        )
    }

    @Test
    fun responseData_requiresTwoStatusBytesAndExactSuccess() {
        assertThrows(MdocNfcEngagementException.ApduFailure::class.java) {
            NdefType4Protocol.responseData(byteArrayOf(0x90.toByte()), "SELECT")
        }
        val status = assertThrows(MdocNfcEngagementException.ApduStatus::class.java) {
            NdefType4Protocol.responseData(hex("016a82"), "READ")
        }
        assertEquals(0x6A82, status.statusWord)
        assertEquals("READ", status.operation)
        assertArrayEquals(byteArrayOf(0x01), NdefType4Protocol.responseData(hex("019000"), "READ"))
    }

    @Test
    fun nlen_mustContainExactlyTwoDataBytes() {
        listOf(SUCCESS, hex("009000"), hex("0000009000")).forEach { nlenResponse ->
            val exchange = Exchange(SUCCESS, SUCCESS, nlenResponse)
            assertThrows(MdocNfcEngagementException.ApduFailure::class.java) {
                NdefType4Protocol.readNdef(transceive = exchange::transceive)
            }
        }
    }

    @Test
    fun bigEndianNlen_controlsAllChunkReads() {
        val firstChunk = ByteArray(255) { it.toByte() }
        val exchange = Exchange(
            SUCCESS,
            SUCCESS,
            hex("01009000"),
            firstChunk + SUCCESS,
            byteArrayOf(0x55) + SUCCESS,
        )

        val result = NdefType4Protocol.readNdef(transceive = exchange::transceive)

        assertEquals(256, result.size)
        assertArrayEquals(firstChunk, result.copyOf(255))
        assertEquals(0x55, result.last().toInt())
        assertArrayEquals(
            NdefType4Protocol.readBinary(offset = 257, length = 1),
            exchange.commands.last(),
        )
    }

    @Test
    fun zeroNlen_returnsEmptyWithoutPayloadReads() {
        val exchange = Exchange(SUCCESS, SUCCESS, hex("00009000"))

        assertArrayEquals(ByteArray(0), NdefType4Protocol.readNdef(transceive = exchange::transceive))
        assertEquals(3, exchange.commands.size)
        assertTrue(NdefType4Protocol.planReadChunks(0).isEmpty())
    }

    @Test
    fun shortAndChunkBoundaryLengths_planExactReads() {
        assertEquals(
            listOf(NdefType4Protocol.ReadChunk(offset = 2, length = 1)),
            NdefType4Protocol.planReadChunks(1),
        )
        assertEquals(
            listOf(
                NdefType4Protocol.ReadChunk(offset = 2, length = 255),
                NdefType4Protocol.ReadChunk(offset = 257, length = 1),
            ),
            NdefType4Protocol.planReadChunks(256),
        )
        assertEquals(
            listOf(
                NdefType4Protocol.ReadChunk(offset = 2, length = 2),
                NdefType4Protocol.ReadChunk(offset = 4, length = 2),
                NdefType4Protocol.ReadChunk(offset = 6, length = 1),
            ),
            NdefType4Protocol.planReadChunks(5, maxChunkBytes = 2),
        )
    }

    @Test
    fun maximumAddressableLength_isAcceptedAndLargerLengthsAreRejected() {
        assertEquals(0xFFFE, NdefType4Protocol.MAX_READABLE_NDEF_BYTES)
        val chunks = NdefType4Protocol.planReadChunks(NdefType4Protocol.MAX_READABLE_NDEF_BYTES)
        assertEquals(257, chunks.size)
        assertEquals(NdefType4Protocol.ReadChunk(offset = 0xFF02, length = 0xFE), chunks.last())
        assertEquals(NdefType4Protocol.MAX_READABLE_NDEF_BYTES, chunks.sumOf { it.length })

        assertThrows(MdocNfcEngagementException.InvalidNdef::class.java) {
            NdefType4Protocol.planReadChunks(NdefType4Protocol.MAX_READABLE_NDEF_BYTES + 1)
        }
        assertThrows(MdocNfcEngagementException.InvalidNdef::class.java) {
            NdefType4Protocol.planReadChunks(MdocNfcHandoverParser.MAX_HANDOVER_SELECT_BYTES + 1)
        }

        val exchange = Exchange(SUCCESS, SUCCESS, hex("ffff9000"))
        assertThrows(MdocNfcEngagementException.InvalidNdef::class.java) {
            NdefType4Protocol.readNdef(transceive = exchange::transceive)
        }
        assertEquals(3, exchange.commands.size)
    }

    @Test
    fun truncatedOrOverlongPayloadResponse_isRejected() {
        listOf(hex("01029000"), hex("010203049000")).forEach { payloadResponse ->
            val exchange = Exchange(SUCCESS, SUCCESS, hex("00039000"), payloadResponse)
            assertThrows(MdocNfcEngagementException.ApduFailure::class.java) {
                NdefType4Protocol.readNdef(transceive = exchange::transceive)
            }
        }
    }

    @Test
    fun transportFailures_areTypedAndCancellationIsPreserved() {
        val failure = assertThrows(MdocNfcEngagementException.ApduFailure::class.java) {
            NdefType4Protocol.readNdef { throw IOException("tag lost") }
        }
        assertTrue(failure.cause is IOException)

        assertThrows(CancellationException::class.java) {
            NdefType4Protocol.readNdef { throw CancellationException("caller cancelled") }
        }
    }

    @Test
    fun invalidReadBounds_failBeforeIssuingCommands() {
        assertThrows(IllegalArgumentException::class.java) {
            NdefType4Protocol.readBinary(offset = 0x10000, length = 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            NdefType4Protocol.readBinary(offset = 0, length = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            NdefType4Protocol.readNdef(maxChunkBytes = 0) { error("must not transceive") }
        }
    }

    private class Exchange(vararg responses: ByteArray) {
        private val responses = ArrayDeque(responses.toList())
        val commands = mutableListOf<ByteArray>()

        fun transceive(command: ByteArray): ByteArray {
            commands += command.copyOf()
            return responses.removeFirst()
        }
    }

    private companion object {
        val SUCCESS = hex("9000")

        fun hex(value: String): ByteArray {
            require(value.length % 2 == 0)
            return ByteArray(value.length / 2) {
                value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
