// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef

import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MdocNfcHandoverParserTest {

    @Test
    fun officialAnnexD33_preservesSelectAndBuildsExactHandoverCbor() {
        val select = hex(OFFICIAL_D33_HANDOVER_SELECT)

        val handover = MdocNfcHandoverParser.parse(select)

        assertArrayEquals(select, handover.handoverSelectBytes)
        assertArrayEquals(hex(OFFICIAL_D33_HANDOVER_CBOR), handover.handoverCbor)
        assertArrayEquals(hex(OFFICIAL_D33_DEVICE_ENGAGEMENT), handover.deviceEngagementBytes)
        assertArrayEquals(
            hex(OFFICIAL_D33_DEVICE_ENGAGEMENT),
            handover.engagement.deviceEngagementBytes,
        )
        // D.3.3 has an LE device address and LE Role, but neither an OOB
        // Service UUID nor DeviceEngagement BLE options.
        assertNull(handover.ble)
        assertFalse(handover.bleSupported)
    }

    @Test
    fun builderEquivalentMessages_mapAllLeRolesAndPreferredUuids() {
        val bothCentral = MdocNfcHandoverParser.parse(handover()).ble!!
        assertTrue(bothCentral.supportsPeripheralServerMode)
        assertTrue(bothCentral.supportsCentralClientMode)
        assertEquals(PERIPHERAL_UUID, bothCentral.peripheralServerModeUuid)
        assertEquals(CENTRAL_UUID, bothCentral.centralClientModeUuid)

        val bothPeripheral = MdocNfcHandoverParser.parse(
            handover(roleValue = 0x02, uuids = listOf(PERIPHERAL_UUID)),
        ).ble!!
        assertTrue(bothPeripheral.supportsPeripheralServerMode)
        assertTrue(bothPeripheral.supportsCentralClientMode)
        assertEquals(PERIPHERAL_UUID, bothPeripheral.peripheralServerModeUuid)
        assertEquals(CENTRAL_UUID, bothPeripheral.centralClientModeUuid)

        val centralOnly = MdocNfcHandoverParser.parse(
            handover(
                deviceEngagement = engagement(peripheral = false),
                roleValue = 0x01,
                uuids = listOf(CENTRAL_UUID),
            ),
        ).ble!!
        assertFalse(centralOnly.supportsPeripheralServerMode)
        assertTrue(centralOnly.supportsCentralClientMode)
        assertNull(centralOnly.peripheralServerModeUuid)
        assertEquals(CENTRAL_UUID, centralOnly.centralClientModeUuid)

        val peripheralOnly = MdocNfcHandoverParser.parse(
            handover(
                deviceEngagement = engagement(central = false),
                roleValue = 0x00,
                uuids = listOf(PERIPHERAL_UUID),
            ),
        ).ble!!
        assertTrue(peripheralOnly.supportsPeripheralServerMode)
        assertFalse(peripheralOnly.supportsCentralClientMode)
        assertEquals(PERIPHERAL_UUID, peripheralOnly.peripheralServerModeUuid)
        assertNull(peripheralOnly.centralClientModeUuid)
    }

    @Test
    fun oobOnlySingleRoleUuid_isMappedWithoutInventingTheOtherMode() {
        val central = MdocNfcHandoverParser.parse(
            handover(
                deviceEngagement = hex(OFFICIAL_D33_DEVICE_ENGAGEMENT),
                roleValue = 0x01,
                uuids = listOf(CENTRAL_UUID),
            ),
        ).ble!!
        assertFalse(central.supportsPeripheralServerMode)
        assertTrue(central.supportsCentralClientMode)
        assertEquals(CENTRAL_UUID, central.centralClientModeUuid)

        val peripheral = MdocNfcHandoverParser.parse(
            handover(
                deviceEngagement = hex(OFFICIAL_D33_DEVICE_ENGAGEMENT),
                roleValue = 0x00,
                uuids = listOf(PERIPHERAL_UUID),
            ),
        ).ble!!
        assertTrue(peripheral.supportsPeripheralServerMode)
        assertFalse(peripheral.supportsCentralClientMode)
        assertEquals(PERIPHERAL_UUID, peripheral.peripheralServerModeUuid)
    }

    @Test
    fun shortAndNormalPayloadLengths_areSupported() {
        val short = MdocNfcHandoverParser.parse(handover())
        val normal = MdocNfcHandoverParser.parse(handover(forceNormalRecords = true))

        assertArrayEquals(short.deviceEngagementBytes, normal.deviceEngagementBytes)
        assertEquals(short.ble, normal.ble)
        assertArrayEquals(
            nfcHandover(handover(forceNormalRecords = true)),
            normal.handoverCbor,
        )
    }

    @Test
    fun duplicateAndMissingDeviceEngagement_areRejected() {
        assertRejected(handover(duplicateDeviceEngagement = true))
        assertRejected(
            ndefMessage(
                listOf(
                    handoverSelectRecord(),
                    bluetoothCarrierRecord(roleValue = 0x03, uuids = listOf(CENTRAL_UUID)),
                ),
            ),
        )
    }

    @Test
    fun chunkedBadMessageFlagsAndInvalidTnf_areRejected() {
        val valid = handover()
        val chunked = valid.copyOf().apply { this[0] = 0xB1.toByte() }
        val missingMb = valid.copyOf().apply { this[0] = 0x11 }
        val reservedTnf = valid.copyOf().apply { this[0] = 0x96.toByte() }
        val unchangedTnf = valid.copyOf().apply { this[0] = 0x97.toByte() }
        val unknownTnfWithType = valid.copyOf().apply { this[0] = 0x95.toByte() }
        val notHandoverSelect = ndefMessage(
            listOf(
                handoverSelectRecord().copy(type = "Hr".toByteArray(Charsets.US_ASCII)),
                bluetoothCarrierRecord(roleValue = 0x03, uuids = listOf(CENTRAL_UUID)),
                deviceEngagementRecord(engagement()),
            ),
        )

        listOf(chunked, missingMb, reservedTnf, unchangedTnf, unknownTnfWithType, notHandoverSelect)
            .forEach(::assertRejected)
    }

    @Test
    fun truncatedMalformedLengthTrailingAndMissingMe_areRejected() {
        val valid = handover()
        val malformedNormalLength = handover(forceNormalRecords = true).copyOf().apply {
            // The first normal record claims a 4096-byte payload.
            this[2] = 0x00
            this[3] = 0x00
            this[4] = 0x10
            this[5] = 0x00
        }

        listOf(
            byteArrayOf(),
            valid.copyOf(1),
            valid.copyOf(5),
            valid.copyOf(valid.size - 1),
            malformedNormalLength,
            valid + 0x00,
            handover(messageEnd = false),
        ).forEach(::assertRejected)
    }

    @Test
    fun oversizedInput_isRejectedBeforeNdefParsing() {
        assertRejected(ByteArray(MdocNfcHandoverParser.MAX_HANDOVER_SELECT_BYTES + 1))
    }

    @Test
    fun malformedBluetoothAdLengthsAndRoles_areRejected() {
        val malformedPayloads = listOf(
            byteArrayOf(0x00),
            hex("031c00"), // Declares three bytes after length, but only two remain.
            ad(AD_LE_ROLE, byteArrayOf()),
            ad(AD_LE_ROLE, byteArrayOf(0x00, 0x01)),
            ad(AD_LE_ROLE, byteArrayOf(0x04)),
            ad(AD_COMPLETE_UUIDS, byteArrayOf()),
            ad(AD_COMPLETE_UUIDS, ByteArray(15)),
            ad(AD_COMPLETE_UUIDS, ByteArray(17)),
        )

        malformedPayloads.forEach { payload -> assertRejected(handover(carrierPayload = payload)) }
    }

    @Test
    fun conflictingRolesAndUuids_areRejected() {
        val roleConflict = handover(
            deviceEngagement = engagement(peripheral = false),
            roleValue = 0x00,
            uuids = listOf(PERIPHERAL_UUID),
        )
        val unknownUuid = handover(uuids = listOf(OTHER_UUID))
        val wrongPreferredUuid = handover(roleValue = 0x03, uuids = listOf(PERIPHERAL_UUID))
        val duplicateRoleConflict = handover(
            carrierPayload = ad(AD_LE_ROLE, byteArrayOf(0x00)) + ad(AD_LE_ROLE, byteArrayOf(0x01)),
        )

        listOf(roleConflict, unknownUuid, wrongPreferredUuid, duplicateRoleConflict).forEach(::assertRejected)
    }

    @Test
    fun strictDeviceEngagementValidation_isReused() {
        assertRejected(handover(deviceEngagement = byteArrayOf(0x00)))
    }

    private fun assertRejected(select: ByteArray) {
        assertThrows(MdocNfcHandoverParseException::class.java) {
            MdocNfcHandoverParser.parse(select)
        }
    }

    private companion object {
        const val AD_COMPLETE_UUIDS = 0x07
        const val AD_LE_ROLE = 0x1C

        const val OFFICIAL_D33_COSE_KEY =
            "a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe" +
                "225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
        const val OFFICIAL_D33_DEVICE_ENGAGEMENT = "a20063312e30018201d818584b$OFFICIAL_D33_COSE_KEY"
        const val OFFICIAL_D33_HANDOVER_SELECT =
            "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f7468" +
                "2e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167" +
                "656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968f" +
                "f289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
        const val OFFICIAL_D33_HANDOVER_CBOR = "8258c3$OFFICIAL_D33_HANDOVER_SELECT" + "f6"

        val PERIPHERAL_UUID: UUID = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val CENTRAL_UUID: UUID = UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f")
        val OTHER_UUID: UUID = UUID.fromString("01020304-0506-0708-090a-0b0c0d0e0f10")

        data class RecordSpec(
            val tnf: Int,
            val type: ByteArray,
            val id: ByteArray?,
            val payload: ByteArray,
            val forceNormal: Boolean = false,
        )

        /** Fixture equivalent to the verifier-independent NfcHandoverSelect.build framing. */
        fun handover(
            deviceEngagement: ByteArray = engagement(),
            roleValue: Int? = 0x03,
            uuids: List<UUID> = listOf(CENTRAL_UUID),
            carrierPayload: ByteArray? = null,
            forceNormalRecords: Boolean = false,
            duplicateDeviceEngagement: Boolean = false,
            messageEnd: Boolean = true,
        ): ByteArray {
            val records = mutableListOf(
                handoverSelectRecord(forceNormalRecords),
                bluetoothCarrierRecord(roleValue, uuids, carrierPayload, forceNormalRecords),
                deviceEngagementRecord(deviceEngagement, forceNormalRecords),
            )
            if (duplicateDeviceEngagement) {
                records.add(deviceEngagementRecord(deviceEngagement, forceNormalRecords))
            }
            return ndefMessage(records, messageEnd)
        }

        fun handoverSelectRecord(forceNormal: Boolean = false): RecordSpec {
            val ac = ndefRecord(
                RecordSpec(
                    tnf = 0x01,
                    type = "ac".toByteArray(Charsets.US_ASCII),
                    id = null,
                    payload = hex("01013001046d646f63"),
                ),
                messageBegin = true,
                messageEnd = true,
            )
            return RecordSpec(
                tnf = 0x01,
                type = "Hs".toByteArray(Charsets.US_ASCII),
                id = null,
                payload = byteArrayOf(0x15) + ac,
                forceNormal = forceNormal,
            )
        }

        fun bluetoothCarrierRecord(
            roleValue: Int?,
            uuids: List<UUID>,
            rawPayload: ByteArray? = null,
            forceNormal: Boolean = false,
        ): RecordSpec = RecordSpec(
            tnf = 0x02,
            type = "application/vnd.bluetooth.le.oob".toByteArray(Charsets.US_ASCII),
            id = byteArrayOf(0x30),
            payload = rawPayload ?: bluetoothOob(roleValue, uuids),
            forceNormal = forceNormal,
        )

        fun deviceEngagementRecord(bytes: ByteArray, forceNormal: Boolean = false): RecordSpec = RecordSpec(
            tnf = 0x04,
            type = "iso.org:18013:deviceengagement".toByteArray(Charsets.US_ASCII),
            id = "mdoc".toByteArray(Charsets.US_ASCII),
            payload = bytes,
            forceNormal = forceNormal,
        )

        fun bluetoothOob(roleValue: Int?, uuids: List<UUID>): ByteArray {
            var result = byteArrayOf()
            if (roleValue != null) result += ad(AD_LE_ROLE, byteArrayOf(roleValue.toByte()))
            if (uuids.isNotEmpty()) {
                result += ad(
                    AD_COMPLETE_UUIDS,
                    uuids.fold(byteArrayOf()) { bytes, uuid -> bytes + littleEndianUuidBytes(uuid) },
                )
            }
            return result
        }

        fun ad(type: Int, data: ByteArray): ByteArray =
            byteArrayOf((data.size + 1).toByte(), type.toByte()) + data

        fun ndefMessage(records: List<RecordSpec>, messageEnd: Boolean = true): ByteArray =
            records.mapIndexed { index, record ->
                ndefRecord(
                    record,
                    messageBegin = index == 0,
                    messageEnd = messageEnd && index == records.lastIndex,
                )
            }.fold(byteArrayOf(), ByteArray::plus)

        fun ndefRecord(record: RecordSpec, messageBegin: Boolean, messageEnd: Boolean): ByteArray {
            val short = !record.forceNormal && record.payload.size < 256
            var header = record.tnf
            if (messageBegin) header = header or 0x80
            if (messageEnd) header = header or 0x40
            if (short) header = header or 0x10
            if (record.id != null) header = header or 0x08
            var result = byteArrayOf(header.toByte(), record.type.size.toByte())
            result += if (short) {
                byteArrayOf(record.payload.size.toByte())
            } else {
                byteArrayOf(
                    (record.payload.size ushr 24).toByte(),
                    (record.payload.size ushr 16).toByte(),
                    (record.payload.size ushr 8).toByte(),
                    record.payload.size.toByte(),
                )
            }
            if (record.id != null) result += record.id.size.toByte()
            result += record.type
            if (record.id != null) result += record.id
            return result + record.payload
        }

        /** Independent canonical test encoder for `[bstr(select), null]`. */
        fun nfcHandover(select: ByteArray): ByteArray {
            val prefix = when {
                select.size < 24 -> byteArrayOf((0x40 or select.size).toByte())
                select.size <= 0xFF -> byteArrayOf(0x58, select.size.toByte())
                else -> byteArrayOf(0x59, (select.size ushr 8).toByte(), select.size.toByte())
            }
            return byteArrayOf(0x82.toByte()) + prefix + select + 0xF6.toByte()
        }

        fun engagement(peripheral: Boolean = true, central: Boolean = true): ByteArray {
            val options = mutableListOf(
                uint(0) to bool(peripheral),
                uint(1) to bool(central),
            )
            if (peripheral) options.add(uint(10) to bytes(uuidBytes(PERIPHERAL_UUID)))
            if (central) options.add(uint(11) to bytes(uuidBytes(CENTRAL_UUID)))
            val bleOptions = map(*options.toTypedArray())
            return map(
                uint(0) to text("1.0"),
                uint(1) to array(uint(1), tag24(bytes(hex(OFFICIAL_D33_COSE_KEY)))),
                uint(2) to array(array(uint(2), uint(1), bleOptions)),
            )
        }

        fun uuidBytes(uuid: UUID): ByteArray =
            ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()

        fun littleEndianUuidBytes(uuid: UUID): ByteArray = uuidBytes(uuid).reversedArray()

        fun map(vararg entries: Pair<ByteArray, ByteArray>): ByteArray =
            header(5, entries.size) + entries.fold(byteArrayOf()) { bytes, entry -> bytes + entry.first + entry.second }

        fun array(vararg items: ByteArray): ByteArray =
            header(4, items.size) + items.fold(byteArrayOf(), ByteArray::plus)

        fun text(value: String): ByteArray {
            val encoded = value.toByteArray(Charsets.UTF_8)
            return header(3, encoded.size) + encoded
        }

        fun bytes(value: ByteArray): ByteArray = header(2, value.size) + value

        fun uint(value: Int): ByteArray = header(if (value >= 0) 0 else 1, if (value >= 0) value else -1 - value)

        fun bool(value: Boolean): ByteArray = byteArrayOf(if (value) 0xF5.toByte() else 0xF4.toByte())

        fun tag24(value: ByteArray): ByteArray = byteArrayOf(0xD8.toByte(), 0x18) + value

        fun header(major: Int, argument: Int): ByteArray {
            require(argument >= 0)
            val initial = major shl 5
            return when {
                argument < 24 -> byteArrayOf((initial or argument).toByte())
                argument <= 0xFF -> byteArrayOf((initial or 24).toByte(), argument.toByte())
                else -> byteArrayOf(
                    (initial or 25).toByte(),
                    (argument ushr 8).toByte(),
                    argument.toByte(),
                )
            }
        }

        fun hex(value: String): ByteArray {
            require(value.length % 2 == 0)
            return ByteArray(value.length / 2) {
                value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
