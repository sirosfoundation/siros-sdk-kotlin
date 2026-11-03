// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import org.siros.sdk.verifier.mdoc.proximity.BleDeviceRetrievalMethod
import org.siros.sdk.verifier.mdoc.proximity.MdocEngagementParseException
import org.siros.sdk.verifier.mdoc.proximity.MdocQrEngagement
import org.siros.sdk.verifier.mdoc.proximity.MdocQrEngagementParser

/** Bounded, transport-independent parser for NFC Forum/ISO 18013-5 static handover. */
object MdocNfcHandoverParser {
    /** Maximum complete NDEF Handover Select message size accepted by [parse]. */
    const val MAX_HANDOVER_SELECT_BYTES: Int = 64 * 1024

    private const val NDEF_MB = 0x80
    private const val NDEF_ME = 0x40
    private const val NDEF_CF = 0x20
    private const val NDEF_SR = 0x10
    private const val NDEF_IL = 0x08
    private const val NDEF_TNF = 0x07

    private const val TNF_EMPTY = 0x00
    private const val TNF_WELL_KNOWN = 0x01
    private const val TNF_MIME = 0x02
    private const val TNF_EXTERNAL = 0x04
    private const val TNF_UNKNOWN = 0x05

    private const val AD_TYPE_COMPLETE_128_BIT_SERVICE_UUIDS = 0x07
    private const val AD_TYPE_LE_ROLE = 0x1C

    private val handoverSelectType = "Hs".toByteArray(Charsets.US_ASCII)
    private val bluetoothLeOobType = "application/vnd.bluetooth.le.oob".toByteArray(Charsets.US_ASCII)
    private val deviceEngagementType = "iso.org:18013:deviceengagement".toByteArray(Charsets.US_ASCII)
    private val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()

    /**
     * Parses a complete raw NDEF Handover Select message.
     *
     * Exactly one `iso.org:18013:deviceengagement` external record is required.
     * Its bytes are base64url-encoded only to reuse [MdocQrEngagementParser]'s
     * strict public validator; all returned transcript bytes retain their
     * original binary form.
     *
     * @throws MdocNfcHandoverParseException for malformed or inconsistent input.
     */
    @JvmStatic
    fun parse(handoverSelectBytes: ByteArray): MdocNfcHandover {
        if (handoverSelectBytes.size > MAX_HANDOVER_SELECT_BYTES) {
            invalid("Handover Select exceeds $MAX_HANDOVER_SELECT_BYTES bytes")
        }
        val records = parseNdefMessage(handoverSelectBytes)
        val first = records.first()
        if (first.tnf != TNF_WELL_KNOWN || !first.type.contentEquals(handoverSelectType)) {
            invalid("Handover Select must begin with a well-known Hs record")
        }

        val deviceEngagementRecords = records.filter {
            it.tnf == TNF_EXTERNAL && it.type.contentEquals(deviceEngagementType)
        }
        if (deviceEngagementRecords.size != 1) {
            invalid("Handover Select must contain exactly one DeviceEngagement record")
        }
        val rawDeviceEngagement = deviceEngagementRecords.single().payload
        val engagement = parseDeviceEngagement(rawDeviceEngagement)
        val carrierRecords = records.filter {
            it.tnf == TNF_MIME && it.type.contentEquals(bluetoothLeOobType)
        }
        val ble = mergeBleMetadata(carrierRecords, engagement.ble)
        val originalSelect = handoverSelectBytes.copyOf()

        return MdocNfcHandover(
            handoverSelectBytes = originalSelect,
            handoverCbor = nfcHandoverCbor(originalSelect),
            engagement = engagement,
            ble = ble,
        )
    }

    private fun parseDeviceEngagement(bytes: ByteArray): MdocQrEngagement = try {
        MdocQrEngagementParser.parse("mdoc:" + base64UrlEncoder.encodeToString(bytes))
    } catch (e: MdocEngagementParseException) {
        throw MdocNfcHandoverParseException("Invalid DeviceEngagement record: ${e.message}", e)
    }

    private fun parseNdefMessage(bytes: ByteArray): List<NdefRecord> {
        if (bytes.isEmpty()) invalid("Handover Select NDEF message is empty")
        val reader = NdefReader(bytes)
        val records = mutableListOf<NdefRecord>()
        var messageEnded = false

        while (reader.remaining > 0) {
            if (messageEnded) invalid("Trailing bytes after the NDEF message-end record")
            val header = reader.u8()
            if (header and NDEF_CF != 0) invalid("Chunked NDEF records are not supported")
            val tnf = header and NDEF_TNF
            if (tnf == 0x06 || tnf == 0x07) invalid("Reserved or unchanged NDEF TNF")

            val messageBegin = header and NDEF_MB != 0
            val messageEnd = header and NDEF_ME != 0
            if (records.isEmpty() && !messageBegin) invalid("First NDEF record does not set MB")
            if (records.isNotEmpty() && messageBegin) invalid("Only the first NDEF record may set MB")

            val shortRecord = header and NDEF_SR != 0
            val hasId = header and NDEF_IL != 0
            val typeLength = reader.u8()
            val payloadLength = if (shortRecord) reader.u8().toLong() else reader.u32()
            if (payloadLength > Int.MAX_VALUE) invalid("NDEF payload length is too large")
            val idLength = if (hasId) reader.u8() else 0

            if (tnf == TNF_EMPTY && (typeLength != 0 || idLength != 0 || payloadLength != 0L)) {
                invalid("Empty-TNF NDEF record has type, ID, or payload data")
            }
            if (tnf == TNF_UNKNOWN && typeLength != 0) {
                invalid("Unknown-TNF NDEF record must not have a type")
            }

            val type = reader.take(typeLength)
            val id = reader.take(idLength)
            val payload = reader.take(payloadLength.toInt())
            records.add(NdefRecord(tnf, type, id, payload))
            messageEnded = messageEnd
        }

        if (!messageEnded) invalid("NDEF message has no message-end record")
        return records
    }

    private fun mergeBleMetadata(
        carrierRecords: List<NdefRecord>,
        engagementBle: BleDeviceRetrievalMethod?,
    ): BleDeviceRetrievalMethod? {
        var role: LeRole? = null
        val advertisedUuids = linkedSetOf<UUID>()

        for (carrier in carrierRecords) {
            var offset = 0
            while (offset < carrier.payload.size) {
                val length = carrier.payload[offset].toInt() and 0xFF
                if (length == 0) invalid("Bluetooth OOB contains a zero-length AD structure")
                val end = offset + 1 + length
                if (end > carrier.payload.size) invalid("Truncated Bluetooth OOB AD structure")
                val type = carrier.payload[offset + 1].toInt() and 0xFF
                val dataStart = offset + 2
                val dataLength = length - 1

                when (type) {
                    AD_TYPE_LE_ROLE -> {
                        if (dataLength != 1) invalid("Bluetooth LE Role AD must contain exactly one byte")
                        val parsedRole = LeRole.fromValue(carrier.payload[dataStart].toInt() and 0xFF)
                        if (role != null && role != parsedRole) invalid("Conflicting Bluetooth LE Role values")
                        role = parsedRole
                    }
                    AD_TYPE_COMPLETE_128_BIT_SERVICE_UUIDS -> {
                        if (dataLength == 0 || dataLength % UUID_BYTES != 0) {
                            invalid("Complete 128-bit Service UUIDs AD has an invalid length")
                        }
                        for (uuidOffset in dataStart until end step UUID_BYTES) {
                            advertisedUuids.add(uuidFromBluetooth(carrier.payload, uuidOffset))
                        }
                    }
                }
                offset = end
            }
        }

        if (engagementBle != null) {
            if (role != null &&
                (role.supportsPeripheral != engagementBle.supportsPeripheralServerMode ||
                    role.supportsCentral != engagementBle.supportsCentralClientMode)
            ) {
                invalid("Bluetooth LE Role conflicts with DeviceEngagement BleOptions")
            }

            val engagementUuids = setOfNotNull(
                engagementBle.peripheralServerModeUuid,
                engagementBle.centralClientModeUuid,
            )
            if (!engagementUuids.containsAll(advertisedUuids)) {
                invalid("Bluetooth OOB Service UUID conflicts with DeviceEngagement BleOptions")
            }

            // NfcHandoverSelect advertises only the preferred mode's UUID when
            // both modes are offered. A different sole UUID is inconsistent.
            if (advertisedUuids.size == 1 && role != null && role.supportsPeripheral && role.supportsCentral) {
                val preferredUuid = if (role.preferPeripheral) {
                    engagementBle.peripheralServerModeUuid
                } else {
                    engagementBle.centralClientModeUuid
                }
                if (advertisedUuids.single() != preferredUuid) {
                    invalid("Bluetooth OOB Service UUID conflicts with the preferred LE Role")
                }
            }
            return engagementBle
        }

        // In particular, Annex D.3.3 supplies an LE address and role but no
        // UUID. Do not invent discovery metadata for the later BLE selector.
        if (role == null || advertisedUuids.isEmpty()) return null

        return when {
            role.supportsPeripheral && !role.supportsCentral -> {
                val uuid = advertisedUuids.singleOrNull()
                    ?: invalid("Peripheral-only handover must advertise exactly one Service UUID")
                BleDeviceRetrievalMethod(
                    supportsPeripheralServerMode = true,
                    supportsCentralClientMode = false,
                    peripheralServerModeUuid = uuid,
                    centralClientModeUuid = null,
                )
            }
            role.supportsCentral && !role.supportsPeripheral -> {
                val uuid = advertisedUuids.singleOrNull()
                    ?: invalid("Central-only handover must advertise exactly one Service UUID")
                BleDeviceRetrievalMethod(
                    supportsPeripheralServerMode = false,
                    supportsCentralClientMode = true,
                    peripheralServerModeUuid = null,
                    centralClientModeUuid = uuid,
                )
            }
            else -> {
                // An unlabelled UUID list cannot populate both keyed UUID
                // fields without DeviceEngagement BleOptions to disambiguate it.
                null
            }
        }
    }

    private fun uuidFromBluetooth(bytes: ByteArray, offset: Int): UUID {
        val bigEndian = bytes.copyOfRange(offset, offset + UUID_BYTES).reversedArray()
        return UUID(ByteBuffer.wrap(bigEndian).long, ByteBuffer.wrap(bigEndian, 8, 8).long)
    }

    /** Canonical CBOR for `NFCHandover = [HandoverSelectBytes, null]`. */
    private fun nfcHandoverCbor(select: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        write(0x82)
        when {
            select.size < 24 -> write(0x40 or select.size)
            select.size <= 0xFF -> {
                write(0x58)
                write(select.size)
            }
            select.size <= 0xFFFF -> {
                write(0x59)
                write(select.size ushr 8)
                write(select.size)
            }
            else -> {
                write(0x5A)
                write(select.size ushr 24)
                write(select.size ushr 16)
                write(select.size ushr 8)
                write(select.size)
            }
        }
        write(select)
        write(0xF6)
    }.toByteArray()

    private fun invalid(message: String): Nothing = throw MdocNfcHandoverParseException(message)

    private const val UUID_BYTES = 16

    private data class NdefRecord(
        val tnf: Int,
        val type: ByteArray,
        @Suppress("unused") val id: ByteArray,
        val payload: ByteArray,
    )

    private enum class LeRole(
        val supportsPeripheral: Boolean,
        val supportsCentral: Boolean,
        val preferPeripheral: Boolean,
    ) {
        PERIPHERAL_ONLY(true, false, true),
        CENTRAL_ONLY(false, true, false),
        BOTH_PERIPHERAL_PREFERRED(true, true, true),
        BOTH_CENTRAL_PREFERRED(true, true, false),
        ;

        companion object {
            fun fromValue(value: Int): LeRole = when (value) {
                0x00 -> PERIPHERAL_ONLY
                0x01 -> CENTRAL_ONLY
                0x02 -> BOTH_PERIPHERAL_PREFERRED
                0x03 -> BOTH_CENTRAL_PREFERRED
                else -> invalid("Unsupported Bluetooth LE Role value: $value")
            }
        }
    }

    private class NdefReader(private val bytes: ByteArray) {
        private var offset = 0

        val remaining: Int
            get() = bytes.size - offset

        fun u8(): Int {
            if (remaining < 1) invalid("Truncated NDEF record header")
            return bytes[offset++].toInt() and 0xFF
        }

        fun u32(): Long {
            if (remaining < 4) invalid("Truncated NDEF payload length")
            return (u8().toLong() shl 24) or (u8().toLong() shl 16) or (u8().toLong() shl 8) or u8().toLong()
        }

        fun take(length: Int): ByteArray {
            if (length < 0 || length > remaining) invalid("NDEF record exceeds the Handover Select message")
            val result = bytes.copyOfRange(offset, offset + length)
            offset += length
            return result
        }
    }
}
