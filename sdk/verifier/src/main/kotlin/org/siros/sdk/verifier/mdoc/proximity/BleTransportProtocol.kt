// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** ISO 18013-5 BLE UUIDs and framing shared by the reader's two GATT roles. */
internal object MdocBleProtocol {
    const val MAX_MESSAGE_SIZE = 2 * 1024 * 1024
    const val DEFAULT_MTU = 23
    const val MAX_ATTRIBUTE_SIZE = 512

    const val STATE_START: Byte = 0x01
    const val STATE_END: Byte = 0x02

    // Table 5: mdoc service, used when the mdoc is the GATT server.
    val MDOC_STATE_UUID: UUID = UUID.fromString("00000001-A123-48CE-896B-4C76973373E6")
    val MDOC_CLIENT2SERVER_UUID: UUID = UUID.fromString("00000002-A123-48CE-896B-4C76973373E6")
    val MDOC_SERVER2CLIENT_UUID: UUID = UUID.fromString("00000003-A123-48CE-896B-4C76973373E6")

    // Table 6: mdoc reader service, used when the reader is the GATT server.
    val READER_STATE_UUID: UUID = UUID.fromString("00000005-A123-48CE-896B-4C76973373E6")
    val READER_CLIENT2SERVER_UUID: UUID = UUID.fromString("00000006-A123-48CE-896B-4C76973373E6")
    val READER_SERVER2CLIENT_UUID: UUID = UUID.fromString("00000007-A123-48CE-896B-4C76973373E6")
    val READER_IDENT_UUID: UUID = UUID.fromString("00000008-A123-48CE-896B-4C76973373E6")

    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    fun maxChunkSize(negotiatedMtu: Int): Int =
        minOf(negotiatedMtu - 3, MAX_ATTRIBUTE_SIZE).coerceAtLeast(DEFAULT_MTU - 3)

    /** Split a whole CBOR message without putting the continuation byte outside the ATT payload limit. */
    fun chunk(message: ByteArray, maxChunkSize: Int): List<ByteArray> {
        require(maxChunkSize > 1) { "maxChunkSize must include the continuation byte and at least one payload byte" }
        if (message.isEmpty()) return listOf(byteArrayOf(0x00))
        val chunks = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < message.size) {
            val end = minOf(offset + maxChunkSize - 1, message.size)
            val continuation = if (end == message.size) 0x00 else 0x01
            chunks.add(byteArrayOf(continuation.toByte()) + message.copyOfRange(offset, end))
            offset = end
        }
        return chunks
    }

    /**
     * §11.1.3.1 Ident = HKDF-SHA256(EDeviceKeyBytes, no salt, "BLEIdent", 16).
     * RFC 5869's absent salt is 32 zero bytes, not a zero-length HMAC key.
     *
     * This is kept local because the verifier intentionally has no keystore dependency.
     * [eDeviceKeyBytes] must be the exact tag-24-wrapped bytes from the QR engagement.
     */
    fun computeIdent(eDeviceKeyBytes: ByteArray): ByteArray {
        val prk = hmacSha256(ByteArray(32), eDeviceKeyBytes)
        return hmacSha256(prk, "BLEIdent".toByteArray(Charsets.US_ASCII) + byteArrayOf(1)).copyOf(16)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key, "HmacSHA256"))
        }.doFinal(data)
}

/** A bounded, reusable reassembler. Every returned value is exactly one whole CBOR message. */
internal class MdocBleReassembler(
    private val maxMessageSize: Int = MdocBleProtocol.MAX_MESSAGE_SIZE,
) {
    private val buffer = java.io.ByteArrayOutputStream()

    @Synchronized
    fun feed(chunk: ByteArray): ByteArray? {
        if (chunk.isEmpty()) {
            buffer.reset()
            throw IllegalArgumentException("BLE chunk must include its continuation byte")
        }
        if (chunk[0] != 0x00.toByte() && chunk[0] != 0x01.toByte()) {
            buffer.reset()
            throw IllegalArgumentException("BLE chunk continuation byte must be 0x00 or 0x01")
        }
        val payloadSize = chunk.size - 1
        if (payloadSize > maxMessageSize - buffer.size()) {
            buffer.reset()
            throw IllegalStateException("Reassembled BLE message exceeds $maxMessageSize bytes")
        }
        buffer.write(chunk, 1, payloadSize)
        if (chunk[0] == 0x01.toByte()) return null
        return buffer.toByteArray().also { buffer.reset() }
    }
}

internal enum class MdocBleStateEvent {
    START,
    END,
}

internal object MdocBleState {
    fun parse(value: ByteArray): MdocBleStateEvent {
        require(value.size == 1) { "BLE State value must contain exactly one byte" }
        return when (value[0]) {
            MdocBleProtocol.STATE_START -> MdocBleStateEvent.START
            MdocBleProtocol.STATE_END -> MdocBleStateEvent.END
            else -> throw IllegalArgumentException("Unknown BLE State value ${value[0]}")
        }
    }
}

internal enum class MdocBleNotificationCharacteristic {
    STATE,
    SERVER_TO_CLIENT,
}

/** Pure state logic for the GATT-client startup sequence, independently testable without Android. */
internal class MdocBleClientHandshake {
    private var stateNotifications = false
    private var dataNotifications = false
    private var startWritten = false

    val ready: Boolean
        @Synchronized get() = stateNotifications && dataNotifications && startWritten

    @Synchronized
    fun onNotifications(characteristic: MdocBleNotificationCharacteristic, enabled: Boolean) {
        when (characteristic) {
            MdocBleNotificationCharacteristic.STATE -> stateNotifications = enabled
            MdocBleNotificationCharacteristic.SERVER_TO_CLIENT -> dataNotifications = enabled
        }
    }

    @Synchronized
    fun onStateStartWritten() {
        startWritten = true
    }
}

/** Pure state logic for STATE_START and Server2Client CCCD handling in the GATT-server role. */
internal class MdocBleServerHandshake {
    private var dataNotifications = false
    private var startReceived = false

    val ready: Boolean
        @Synchronized get() = dataNotifications && startReceived

    val started: Boolean
        @Synchronized get() = startReceived

    @Synchronized
    fun onServer2ClientNotifications(enabled: Boolean) {
        dataNotifications = enabled
    }

    @Synchronized
    fun onState(value: ByteArray): MdocBleStateEvent =
        MdocBleState.parse(value).also { event ->
            if (event == MdocBleStateEvent.START) startReceived = true
        }
}
