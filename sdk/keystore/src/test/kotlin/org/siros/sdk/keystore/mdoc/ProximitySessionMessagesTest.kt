// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProximitySessionMessagesTest {

    @Test
    fun buildAndParseSessionData_roundTripsWithDataOnly() {
        val data = byteArrayOf(1, 2, 3, 4)
        val bytes = ProximitySessionMessages.buildSessionData(encryptedData = data)

        val decoded = CBORObject.DecodeFromBytes(bytes)
        assertArrayEquals(data, decoded[CBORObject.FromObject("data")].GetByteString())
        assertNull(decoded[CBORObject.FromObject("status")])
    }

    @Test
    fun buildSessionData_statusOnly_omitsData() {
        val bytes = ProximitySessionMessages.buildSessionData(
            encryptedData = null,
            status = ProximitySessionMessages.StatusCode.SESSION_TERMINATION,
        )

        val decoded = CBORObject.DecodeFromBytes(bytes)
        assertNull(decoded[CBORObject.FromObject("data")])
        assertEquals(20L, decoded[CBORObject.FromObject("status")].AsInt64Value())
    }

    @Test
    fun parseSessionEstablishment_extractsEReaderKeyAndData() {
        val eReaderKey = CBORObject.FromObjectAndTag(
            CBORObject.NewMap().apply { this[CBORObject.FromObject(1L)] = CBORObject.FromObject(2L) }.EncodeToBytes(),
            24,
        )
        val map = CBORObject.NewMap()
        map["eReaderKey"] = eReaderKey
        map["data"] = CBORObject.FromObject(byteArrayOf(9, 8, 7))

        val parsed = ProximitySessionMessages.parseSessionEstablishment(map.EncodeToBytes())

        assertArrayEquals(eReaderKey.EncodeToBytes(), parsed.eReaderKeyBytes)
        assertArrayEquals(byteArrayOf(9, 8, 7), parsed.encryptedData)
    }

    @Test
    fun parseSessionEstablishment_missingEReaderKey_throws() {
        val map = CBORObject.NewMap()
        map["data"] = CBORObject.FromObject(byteArrayOf(1))
        try {
            ProximitySessionMessages.parseSessionEstablishment(map.EncodeToBytes())
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}

class BleMessageChunkerTest {

    @Test
    fun chunk_messageSmallerThanMaxSize_singleLastChunk() {
        val message = byteArrayOf(1, 2, 3)
        val chunks = BleMessageChunker.chunk(message, maxChunkSize = 10)

        assertEquals(1, chunks.size)
        assertEquals(0x00, chunks[0][0].toInt())
        assertArrayEquals(message, chunks[0].copyOfRange(1, chunks[0].size))
    }

    @Test
    fun chunk_emptyMessage_singleEmptyLastChunk() {
        val chunks = BleMessageChunker.chunk(ByteArray(0), maxChunkSize = 10)

        assertEquals(1, chunks.size)
        assertArrayEquals(byteArrayOf(0x00), chunks[0])
    }

    @Test
    fun chunk_messageLargerThanMaxSize_splitsWithCorrectPrefixes() {
        val message = ByteArray(25) { it.toByte() }
        val chunks = BleMessageChunker.chunk(message, maxChunkSize = 10)

        assertEquals(3, chunks.size)
        assertEquals(0x01, chunks[0][0].toInt())
        assertEquals(0x01, chunks[1][0].toInt())
        assertEquals(0x00, chunks[2][0].toInt())
        assertEquals(11, chunks[0].size) // prefix + 10
        assertEquals(11, chunks[1].size)
        assertEquals(6, chunks[2].size) // prefix + 5 remaining
    }

    @Test
    fun reassembler_reconstructsOriginalMessage() {
        val message = ByteArray(517) { (it % 251).toByte() }
        val chunks = BleMessageChunker.chunk(message, maxChunkSize = 100)
        val reassembler = BleMessageChunker.Reassembler()

        var result: ByteArray? = null
        for (chunk in chunks) {
            val r = reassembler.feed(chunk)
            if (r != null) {
                assertTrue("only the last chunk should yield a result", chunk === chunks.last())
                result = r
            }
        }

        assertArrayEquals(message, result)
    }

    @Test
    fun reassembler_resetsAfterCompleteMessage_forNextMessage() {
        val reassembler = BleMessageChunker.Reassembler()
        val first = "first".toByteArray()
        val second = "second".toByteArray()

        for (chunk in BleMessageChunker.chunk(first, maxChunkSize = 3)) reassembler.feed(chunk)
        var secondResult: ByteArray? = null
        for (chunk in BleMessageChunker.chunk(second, maxChunkSize = 3)) secondResult = reassembler.feed(chunk) ?: secondResult

        assertArrayEquals(second, secondResult)
    }
}
