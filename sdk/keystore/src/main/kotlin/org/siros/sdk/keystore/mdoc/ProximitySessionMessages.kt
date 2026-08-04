// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject

/**
 * ISO 18013-5 §12.2.4 `SessionEstablishment`/`SessionData` CBOR message
 * framing, carried over the BLE transport built in [BleMessageChunker].
 * ```
 * SessionEstablishment = { "eReaderKey": EReaderKeyBytes, "data": bstr }
 * SessionData = { ? "data": bstr, ? "status": uint }
 * ```
 */
object ProximitySessionMessages {

    /** A parsed `SessionEstablishment` message: the reader's ephemeral public key bytes plus the encrypted mdoc request. */
    data class SessionEstablishment(val eReaderKeyBytes: ByteArray, val encryptedData: ByteArray)

    fun parseSessionEstablishment(bytes: ByteArray): SessionEstablishment {
        val map = CBORObject.DecodeFromBytes(bytes)
        val eReaderKey = map[CBORObject.FromObject("eReaderKey")]
            ?: throw IllegalArgumentException("SessionEstablishment missing eReaderKey")
        val data = map[CBORObject.FromObject("data")]
            ?: throw IllegalArgumentException("SessionEstablishment missing data")
        return SessionEstablishment(eReaderKeyBytes = eReaderKey.EncodeToBytes(), encryptedData = data.GetByteString())
    }

    /** Build a `SessionData` message carrying an encrypted mdoc response, optionally with a status code. */
    fun buildSessionData(encryptedData: ByteArray?, status: Int? = null): ByteArray {
        val map = CBORObject.NewMap()
        if (encryptedData != null) map["data"] = CBORObject.FromObject(encryptedData)
        if (status != null) map["status"] = CBORObject.FromObject(status)
        return map.EncodeToBytes()
    }

    /** ISO 18013-5 Table 15 status codes. */
    object StatusCode {
        const val SESSION_ENCRYPTION_ERROR = 10
        const val CBOR_DECODING_ERROR = 11
        const val SESSION_TERMINATION = 20
    }
}

/**
 * ISO 18013-5 §11.1.3.4 BLE message chunking: splits an application message
 * into MTU-3-sized parts, each prefixed `0x01` (more coming) or `0x00`
 * (last part), and reassembles a sequence of received parts back into the
 * original message. Shared by both BLE roles (central client / peripheral
 * server) - the framing is identical regardless of which side is the GATT
 * client or server.
 */
object BleMessageChunker {

    /**
     * Split [message] into chunks whose TOTAL wire size (1-byte prefix +
     * payload) never exceeds [maxChunkSize] - i.e. [maxChunkSize] is the
     * already MTU-3-adjusted (and 512-byte-attribute-capped) limit on what
     * can actually go out over the air in one write/notify, not a
     * payload-only figure. Each payload slice is therefore at most
     * `maxChunkSize - 1` bytes, reserving room for the prefix byte - an
     * earlier version of this function took [maxChunkSize] payload bytes
     * and then added the prefix on top, silently producing chunks one byte
     * OVER the caller's limit (caught via a real BLE notifyCharacteristicChanged
     * rejection: "Notification should not be longer than max length of an
     * attribute value").
     */
    fun chunk(message: ByteArray, maxChunkSize: Int): List<ByteArray> {
        require(maxChunkSize > 1) { "maxChunkSize must allow at least 1 payload byte alongside the prefix" }
        val payloadSize = maxChunkSize - 1
        if (message.isEmpty()) return listOf(byteArrayOf(0x00))
        val chunks = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < message.size) {
            val end = minOf(offset + payloadSize, message.size)
            val isLast = end == message.size
            val prefix = if (isLast) 0x00.toByte() else 0x01.toByte()
            chunks.add(byteArrayOf(prefix) + message.copyOfRange(offset, end))
            offset = end
        }
        return chunks
    }

    /** Accumulates incoming chunks and reports the reassembled message once the last (`0x00`-prefixed) chunk arrives. */
    class Reassembler {
        private val buffer = java.io.ByteArrayOutputStream()

        /** Feed one received chunk (including its prefix byte). Returns the complete message once the last part arrives, null otherwise. */
        fun feed(chunk: ByteArray): ByteArray? {
            require(chunk.isNotEmpty()) { "chunk must include its continuation-byte prefix" }
            val isLast = chunk[0] == 0x00.toByte()
            buffer.write(chunk, 1, chunk.size - 1)
            if (!isLast) return null
            val result = buffer.toByteArray()
            buffer.reset()
            return result
        }
    }
}
