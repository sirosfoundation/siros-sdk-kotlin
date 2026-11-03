// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import java.util.UUID

class MdocQrEngagementParserTest {

    @Test
    fun officialIsoD33DeviceEngagement_preservesExactTranscriptAndIdentInputs() {
        // ISO/IEC 18013-5 second-edition CD ballot-resolution draft, Annex
        // D.3.3's DeviceEngagement auxiliary-data record. It has no retrieval
        // methods key, which is useful coverage independent of our BLE fixture.
        val bytes = hex(OFFICIAL_D33_DEVICE_ENGAGEMENT)

        val engagement = MdocQrEngagementParser.parse(uri(bytes))

        assertArrayEquals(bytes, engagement.deviceEngagementBytes)
        assertArrayEquals(hex("d818584b$OFFICIAL_D33_COSE_KEY"), engagement.eDeviceKeyBytes)
        assertArrayEquals(byteArrayOf(0xf6.toByte()), engagement.qrHandover)
        assertNull(engagement.ble)
    }

    @Test
    fun constructedBothBleModes_extractsFlagsUuidsAndExactTaggedKey() {
        val bytes = engagement()
        val expectedEDeviceKey = tag24(bytes(COSE_KEY))

        val engagement = MdocQrEngagementParser.parse(uri(bytes))

        assertArrayEquals(bytes, engagement.deviceEngagementBytes)
        assertArrayEquals(expectedEDeviceKey, engagement.eDeviceKeyBytes)
        val ble = engagement.ble!!
        assertTrue(ble.supportsPeripheralServerMode)
        assertTrue(ble.supportsCentralClientMode)
        assertEquals(PERIPHERAL_UUID, ble.peripheralServerModeUuid)
        assertEquals(CENTRAL_UUID, ble.centralClientModeUuid)
    }

    @Test
    fun constructedSingleBleModes_requireOnlyTheEnabledModeUuid() {
        val centralOnly = MdocQrEngagementParser.parse(uri(engagement(peripheral = false))).ble!!
        assertFalse(centralOnly.supportsPeripheralServerMode)
        assertTrue(centralOnly.supportsCentralClientMode)
        assertNull(centralOnly.peripheralServerModeUuid)
        assertEquals(CENTRAL_UUID, centralOnly.centralClientModeUuid)

        val peripheralOnly = MdocQrEngagementParser.parse(uri(engagement(central = false))).ble!!
        assertTrue(peripheralOnly.supportsPeripheralServerMode)
        assertFalse(peripheralOnly.supportsCentralClientMode)
        assertEquals(PERIPHERAL_UUID, peripheralOnly.peripheralServerModeUuid)
        assertNull(peripheralOnly.centralClientModeUuid)
    }

    @Test
    fun nonMinimalButWellFormedEncoding_isNeverReencoded() {
        val canonical = engagement()
        // Encode top-level key 0 as 0x18 0x00 and tag 24 as 0xd9 0x00 0x18.
        val nonMinimalKey = byteArrayOf(0xa3.toByte(), 0x18, 0x00) + canonical.copyOfRange(2, canonical.size)
        val bytes = replaceFirst(nonMinimalKey, hex("d818"), hex("d90018"))

        val parsed = MdocQrEngagementParser.parse(uri(bytes))

        assertArrayEquals(bytes, parsed.deviceEngagementBytes)
        assertArrayEquals(tag24NonMinimal(bytes(COSE_KEY)), parsed.eDeviceKeyBytes)
    }

    @Test
    fun malformedBase64UrlAndWrongSchemes_areRejected() {
        val valid = uri(engagement())
        val invalid = listOf(
            "",
            "https:${valid.removePrefix("mdoc:")}",
            "MDOC:${valid.removePrefix("mdoc:")}",
            "mdoc:===",
            "mdoc:abc=",
            "mdoc:a+b/",
            "mdoc:a",
            "mdoc:Zh", // non-zero unused bits; canonical encoding would be Zg
            " $valid",
        )
        invalid.forEach {
            assertThrows(MdocEngagementParseException::class.java) { MdocQrEngagementParser.parse(it) }
        }
    }

    @Test
    fun malformedTruncatedIndefiniteAndTrailingCbor_areRejected() {
        val valid = engagement()
        val invalid = listOf(
            ByteArray(0),
            valid.copyOf(valid.size - 1),
            hex("bf0063312e30ff"),
            valid + 0x00,
            valid + 0xf6.toByte(),
        )
        invalid.forEach { assertCborRejected(it) }
    }

    @Test
    fun unsupportedEngagementCipherRetrievalVersionsAndTypes_areRejected() {
        val invalid = listOf(
            engagement(version = "1.1"),
            engagement(cipherSuite = 2),
            engagement(retrieval = bleRetrieval(type = 1)),
            engagement(retrieval = bleRetrieval(type = 3)),
            engagement(retrieval = bleRetrieval(version = 2)),
            engagement(retrieval = array(uint(2), uint(1), uint(2), bleOptions())),
            engagement(rawExtraTopLevelEntry = uint(3) to text("unknown")),
        )
        invalid.forEach { assertCborRejected(it) }
    }

    @Test
    fun duplicateMapKeys_areRejectedEvenWithDifferentIntegerEncodings() {
        val canonical = engagement()
        val duplicateVersion = byteArrayOf(0xa4.toByte()) +
            canonical.copyOfRange(1, canonical.size) +
            hex("1800") + text("1.0")
        val duplicateBleOption = engagement(
            retrieval = bleRetrieval(
                options = map(
                    uint(0) to bool(true),
                    uint(1) to bool(true),
                    uint(10) to bytes(uuidBytes(PERIPHERAL_UUID)),
                    uint(11) to bytes(uuidBytes(CENTRAL_UUID)),
                    hex("1800") to bool(true),
                ),
            ),
        )

        assertCborRejected(duplicateVersion)
        assertCborRejected(duplicateBleOption)
    }

    @Test
    fun duplicateCoseKeyLabels_areRejected() {
        val duplicateKty = byteArrayOf(0xa5.toByte()) +
            COSE_KEY.copyOfRange(1, COSE_KEY.size) + uint(1) + uint(2)
        assertCborRejected(engagement(eDeviceKey = tag24(bytes(duplicateKty))))
    }

    @Test
    fun missingInconsistentAndUnknownBleOptions_areRejected() {
        val invalid = listOf(
            engagement(retrieval = bleRetrieval(options = bleOptions(peripheral = null))),
            engagement(retrieval = bleRetrieval(options = bleOptions(central = null))),
            engagement(retrieval = bleRetrieval(options = bleOptions(peripheral = true, peripheralUuid = null))),
            engagement(retrieval = bleRetrieval(options = bleOptions(central = true, centralUuid = null))),
            engagement(retrieval = bleRetrieval(options = bleOptions(peripheral = false, peripheralUuid = uuidBytes(PERIPHERAL_UUID)))),
            engagement(retrieval = bleRetrieval(options = bleOptions(central = false, centralUuid = uuidBytes(CENTRAL_UUID)))),
            engagement(retrieval = bleRetrieval(options = bleOptions(peripheral = false, central = false))),
            engagement(retrieval = bleRetrieval(options = bleOptions(extraEntry = uint(2) to bool(true)))),
        )
        invalid.forEach { assertCborRejected(it) }
    }

    @Test
    fun badUuidTypesAndSizes_areRejected() {
        val invalid = listOf(
            engagement(retrieval = bleRetrieval(options = bleOptions(peripheralUuid = ByteArray(15)))),
            engagement(retrieval = bleRetrieval(options = bleOptions(centralUuid = ByteArray(17)))),
            engagement(
                retrieval = bleRetrieval(
                    options = map(
                        uint(0) to bool(true),
                        uint(1) to bool(true),
                        uint(10) to text(PERIPHERAL_UUID.toString()),
                        uint(11) to bytes(uuidBytes(CENTRAL_UUID)),
                    ),
                ),
            ),
        )
        invalid.forEach { assertCborRejected(it) }
    }

    @Test
    fun malformedOrUnsupportedEDeviceKey_isRejected() {
        val invalid = listOf(
            engagement(eDeviceKey = bytes(COSE_KEY)),
            engagement(eDeviceKey = tag(25, bytes(COSE_KEY))),
            engagement(eDeviceKey = tag24(text("not bytes"))),
            engagement(eDeviceKey = tag24(bytes(COSE_KEY.copyOf(COSE_KEY.size - 1)))),
            engagement(eDeviceKey = tag24(bytes(COSE_KEY + 0x00))),
            engagement(eDeviceKey = tag24(bytes(coseKey(x = ByteArray(31))))),
            engagement(eDeviceKey = tag24(bytes(coseKey(curve = 2)))),
            engagement(eDeviceKey = tag24(bytes(coseKey(keyType = 1)))),
        )
        invalid.forEach { assertCborRejected(it) }
    }

    @Test
    fun oversizedInput_isRejectedBeforeCborAllocation() {
        val oversized = ByteArray(MdocQrEngagementParser.MAX_DEVICE_ENGAGEMENT_BYTES + 1)
        assertCborRejected(oversized)
    }

    private fun assertCborRejected(bytes: ByteArray) {
        assertThrows(MdocEngagementParseException::class.java) {
            MdocQrEngagementParser.parse(uri(bytes))
        }
    }

    private companion object {
        const val OFFICIAL_D33_COSE_KEY =
            "a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe" +
                "225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
        const val OFFICIAL_D33_DEVICE_ENGAGEMENT = "a20063312e30018201d818584b$OFFICIAL_D33_COSE_KEY"

        val COSE_KEY = hex(OFFICIAL_D33_COSE_KEY)
        val PERIPHERAL_UUID: UUID = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val CENTRAL_UUID: UUID = UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f")

        fun engagement(
            version: String = "1.0",
            cipherSuite: Long = 1,
            peripheral: Boolean? = true,
            central: Boolean? = true,
            peripheralUuid: ByteArray? = if (peripheral == true) uuidBytes(PERIPHERAL_UUID) else null,
            centralUuid: ByteArray? = if (central == true) uuidBytes(CENTRAL_UUID) else null,
            retrieval: ByteArray? = bleRetrieval(
                options = bleOptions(peripheral, central, peripheralUuid, centralUuid),
            ),
            eDeviceKey: ByteArray = tag24(bytes(COSE_KEY)),
            rawExtraTopLevelEntry: Pair<ByteArray, ByteArray>? = null,
        ): ByteArray {
            val entries = mutableListOf(
                uint(0) to text(version),
                uint(1) to array(uint(cipherSuite), eDeviceKey),
            )
            if (retrieval != null) entries.add(uint(2) to array(retrieval))
            if (rawExtraTopLevelEntry != null) entries.add(rawExtraTopLevelEntry)
            return map(*entries.toTypedArray())
        }

        fun bleRetrieval(type: Long = 2, version: Long = 1, options: ByteArray = bleOptions()): ByteArray =
            array(uint(type), uint(version), options)

        fun bleOptions(
            peripheral: Boolean? = true,
            central: Boolean? = true,
            peripheralUuid: ByteArray? = if (peripheral == true) uuidBytes(PERIPHERAL_UUID) else null,
            centralUuid: ByteArray? = if (central == true) uuidBytes(CENTRAL_UUID) else null,
            extraEntry: Pair<ByteArray, ByteArray>? = null,
        ): ByteArray {
            val entries = mutableListOf<Pair<ByteArray, ByteArray>>()
            if (peripheral != null) entries.add(uint(0) to bool(peripheral))
            if (central != null) entries.add(uint(1) to bool(central))
            if (peripheralUuid != null) entries.add(uint(10) to bytes(peripheralUuid))
            if (centralUuid != null) entries.add(uint(11) to bytes(centralUuid))
            if (extraEntry != null) entries.add(extraEntry)
            return map(*entries.toTypedArray())
        }

        fun coseKey(keyType: Long = 2, curve: Long = 1, x: ByteArray = ByteArray(32) { 1 }): ByteArray = map(
            uint(1) to uint(keyType),
            uint(-1) to uint(curve),
            uint(-2) to bytes(x),
            uint(-3) to bytes(ByteArray(32) { 2 }),
        )

        fun uri(bytes: ByteArray): String =
            "mdoc:" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun uuidBytes(uuid: UUID): ByteArray {
            val bytes = ByteArray(16)
            val msb = uuid.mostSignificantBits
            val lsb = uuid.leastSignificantBits
            for (i in 0 until 8) bytes[i] = (msb ushr (8 * (7 - i))).toByte()
            for (i in 0 until 8) bytes[8 + i] = (lsb ushr (8 * (7 - i))).toByte()
            return bytes
        }

        fun map(vararg entries: Pair<ByteArray, ByteArray>): ByteArray =
            header(5, entries.size.toLong()) + entries.flatMap { listOf(it.first, it.second) }.reduce(ByteArray::plus)

        fun array(vararg items: ByteArray): ByteArray =
            header(4, items.size.toLong()) + items.reduce(ByteArray::plus)

        fun text(value: String): ByteArray {
            val encoded = value.toByteArray(Charsets.UTF_8)
            return header(3, encoded.size.toLong()) + encoded
        }

        fun bytes(value: ByteArray): ByteArray = header(2, value.size.toLong()) + value

        fun uint(value: Long): ByteArray = if (value >= 0) header(0, value) else header(1, -1 - value)

        fun bool(value: Boolean): ByteArray = byteArrayOf(if (value) 0xf5.toByte() else 0xf4.toByte())

        fun tag24(value: ByteArray): ByteArray = tag(24, value)

        fun tag24NonMinimal(value: ByteArray): ByteArray = hex("d90018") + value

        fun tag(number: Long, value: ByteArray): ByteArray = header(6, number) + value

        fun header(major: Int, argument: Long): ByteArray {
            require(argument >= 0)
            val initial = major shl 5
            return when {
                argument < 24 -> byteArrayOf((initial or argument.toInt()).toByte())
                argument <= 0xff -> byteArrayOf((initial or 24).toByte(), argument.toByte())
                argument <= 0xffff -> byteArrayOf(
                    (initial or 25).toByte(),
                    (argument ushr 8).toByte(),
                    argument.toByte(),
                )
                else -> throw IllegalArgumentException("test encoder only needs lengths up to 65535")
            }
        }

        fun hex(value: String): ByteArray {
            require(value.length % 2 == 0)
            return ByteArray(value.length / 2) {
                value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
            }
        }

        fun replaceFirst(source: ByteArray, target: ByteArray, replacement: ByteArray): ByteArray {
            val index = source.indices.firstOrNull { start ->
                start + target.size <= source.size && source.copyOfRange(start, start + target.size).contentEquals(target)
            } ?: throw IllegalArgumentException("target not found")
            return source.copyOfRange(0, index) + replacement + source.copyOfRange(index + target.size, source.size)
        }
    }
}
