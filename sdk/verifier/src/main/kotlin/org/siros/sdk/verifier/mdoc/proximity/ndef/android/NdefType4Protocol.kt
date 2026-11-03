// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef.android

import kotlinx.coroutines.CancellationException
import org.siros.sdk.verifier.mdoc.proximity.ndef.MdocNfcHandoverParser

/** Pure NFC Forum Type 4 APDU framing and NDEF-file read planning. */
internal object NdefType4Protocol {
    internal const val NDEF_APPLICATION_OPERATION = "SELECT NDEF Tag Application"
    internal const val NDEF_FILE_OPERATION = "SELECT NDEF data file E104"
    internal const val NLEN_OPERATION = "READ NLEN"

    private const val NLEN_BYTES = 2
    private const val STATUS_BYTES = 2
    private const val MAX_READ_BINARY_OFFSET = 0xFFFF

    /** One-byte Le is used throughout, so no request asks for the ambiguous Le=0 / 256 bytes. */
    internal const val MAX_READ_CHUNK_BYTES = 0xFF

    /**
     * NDEF data begins after NLEN. P1/P2 limit the final readable file offset to FFFF,
     * making FFFE the largest complete NDEF message readable with these short APDUs.
     */
    internal val MAX_READABLE_NDEF_BYTES: Int = minOf(
        MdocNfcHandoverParser.MAX_HANDOVER_SELECT_BYTES,
        MAX_READ_BINARY_OFFSET - NLEN_BYTES + 1,
    )

    private val NDEF_APPLICATION_AID = byteArrayOf(
        0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01,
    )
    private val NDEF_FILE_ID = byteArrayOf(0xE1.toByte(), 0x04)

    internal data class ReadChunk(val offset: Int, val length: Int)

    internal fun selectNdefApplication(): ByteArray = byteArrayOf(
        0x00, 0xA4.toByte(), 0x04, 0x00, NDEF_APPLICATION_AID.size.toByte(),
    ) + NDEF_APPLICATION_AID + byteArrayOf(0x00)

    internal fun selectNdefFile(): ByteArray =
        byteArrayOf(0x00, 0xA4.toByte(), 0x00, 0x0C, NDEF_FILE_ID.size.toByte()) + NDEF_FILE_ID

    internal fun readNlen(): ByteArray = readBinary(offset = 0, length = NLEN_BYTES)

    internal fun readBinary(offset: Int, length: Int): ByteArray {
        require(offset in 0..MAX_READ_BINARY_OFFSET) { "READ BINARY offset is outside P1/P2" }
        require(length in 1..MAX_READ_CHUNK_BYTES) { "READ BINARY length must use a non-zero one-byte Le" }
        return byteArrayOf(
            0x00,
            0xB0.toByte(),
            (offset ushr 8).toByte(),
            offset.toByte(),
            length.toByte(),
        )
    }

    /** Returns the response data only after exact SW=9000 and, when supplied, an exact data length. */
    internal fun responseData(
        response: ByteArray,
        operation: String,
        expectedLength: Int? = null,
    ): ByteArray {
        if (response.size < STATUS_BYTES) {
            throw MdocNfcEngagementException.ApduFailure(
                operation,
                "$operation returned a truncated APDU response",
            )
        }
        val statusWord = ((response[response.size - 2].toInt() and 0xFF) shl 8) or
            (response.last().toInt() and 0xFF)
        if (statusWord != SW_SUCCESS) {
            throw MdocNfcEngagementException.ApduStatus(operation, statusWord)
        }
        val dataLength = response.size - STATUS_BYTES
        if (expectedLength != null && dataLength != expectedLength) {
            throw MdocNfcEngagementException.ApduFailure(
                operation,
                "$operation returned $dataLength data bytes; expected exactly $expectedLength",
            )
        }
        return response.copyOfRange(0, dataLength)
    }

    /** Plans NDEF payload reads; offsets include the two-byte NLEN prefix in the NDEF file. */
    internal fun planReadChunks(
        ndefLength: Int,
        maxChunkBytes: Int = MAX_READ_CHUNK_BYTES,
    ): List<ReadChunk> {
        if (maxChunkBytes !in 1..MAX_READ_CHUNK_BYTES) {
            throw IllegalArgumentException("Read chunk size must be in 1..$MAX_READ_CHUNK_BYTES")
        }
        if (ndefLength < 0) throw MdocNfcEngagementException.InvalidNdef("NDEF length is negative")
        if (ndefLength > MdocNfcHandoverParser.MAX_HANDOVER_SELECT_BYTES) {
            throw MdocNfcEngagementException.InvalidNdef(
                "NDEF message exceeds parser maximum of ${MdocNfcHandoverParser.MAX_HANDOVER_SELECT_BYTES} bytes",
            )
        }
        if (ndefLength > MAX_READABLE_NDEF_BYTES) {
            throw MdocNfcEngagementException.InvalidNdef(
                "NDEF message exceeds the Type 4 short READ BINARY address range",
            )
        }

        val chunks = mutableListOf<ReadChunk>()
        var messageOffset = 0
        while (messageOffset < ndefLength) {
            val length = minOf(maxChunkBytes, ndefLength - messageOffset)
            chunks.add(ReadChunk(offset = NLEN_BYTES + messageOffset, length = length))
            messageOffset += length
        }
        return chunks
    }

    /**
     * Reads the exact NDEF bytes from a selected Type 4 NDEF file. No NDEF parsing or re-encoding occurs here.
     */
    internal fun readNdef(
        maxChunkBytes: Int = MAX_READ_CHUNK_BYTES,
        transceive: (ByteArray) -> ByteArray,
    ): ByteArray {
        // Validate the chunk bound before issuing any command, including for a zero-length NDEF message.
        if (maxChunkBytes !in 1..MAX_READ_CHUNK_BYTES) {
            throw IllegalArgumentException("Read chunk size must be in 1..$MAX_READ_CHUNK_BYTES")
        }

        responseData(exchange(NDEF_APPLICATION_OPERATION, selectNdefApplication(), transceive), NDEF_APPLICATION_OPERATION)
        responseData(exchange(NDEF_FILE_OPERATION, selectNdefFile(), transceive), NDEF_FILE_OPERATION)

        val nlenData = responseData(
            exchange(NLEN_OPERATION, readNlen(), transceive),
            NLEN_OPERATION,
            expectedLength = NLEN_BYTES,
        )
        val ndefLength = ((nlenData[0].toInt() and 0xFF) shl 8) or (nlenData[1].toInt() and 0xFF)
        val chunks = planReadChunks(ndefLength, maxChunkBytes)
        val ndef = ByteArray(ndefLength)
        var destinationOffset = 0
        for (chunk in chunks) {
            val operation = "READ NDEF at file offset ${chunk.offset}"
            val data = responseData(
                exchange(operation, readBinary(chunk.offset, chunk.length), transceive),
                operation,
                expectedLength = chunk.length,
            )
            data.copyInto(ndef, destinationOffset)
            destinationOffset += data.size
        }
        return ndef
    }

    private fun exchange(
        operation: String,
        command: ByteArray,
        transceive: (ByteArray) -> ByteArray,
    ): ByteArray = try {
        transceive(command)
    } catch (e: CancellationException) {
        throw e
    } catch (e: MdocNfcEngagementException) {
        throw e
    } catch (e: Exception) {
        throw MdocNfcEngagementException.ApduFailure(operation, "$operation failed", e)
    }

    private const val SW_SUCCESS = 0x9000
}
