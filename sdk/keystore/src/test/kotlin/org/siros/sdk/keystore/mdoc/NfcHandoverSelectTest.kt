// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.UUID

/**
 * Verifies [NfcHandoverSelect.build] against the real ISO/IEC 18013-5
 * second-edition CD ballot-resolution draft, Annex D.3.3 "NFC Handover
 * select" worked example. The hex below was extracted from the primary
 * source PDF via `pdftotext -layout` (a real text layer, not OCR) and
 * verified byte-for-byte with a standalone NDEF-record parser against
 * §9.2/§11.1.2's normative structure before being hardcoded here - see
 * [NfcHandoverSelect]'s doc comment.
 */
class NfcHandoverSelectTest {

    /** Annex D.3.3's full Handover Select NDEF message (3 records: Hs, BLE carrier config, device engagement). */
    private val d33HandoverSelectHex =
        "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f7468" +
            "2e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167" +
            "656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968f" +
            "f289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"

    /** The `DeviceEngagement` CBOR embedded in D.3.3's aux record (its own worked example, distinct from D.3.1's). */
    private val d33DeviceEngagementHex =
        "a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b6" +
            "24343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"

    private fun hex(s: String): ByteArray {
        val clean = s.replace(" ", "").replace("\n", "")
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    @Test
    fun officialVector_decodesToTheExpectedThreeRecordStructure() {
        val bytes = hex(d33HandoverSelectHex)

        // Record 1: "Hs" - MB=1,ME=0,SR=1,TNF=well-known(1) -> header 0x91.
        assertEquals(0x91, bytes[0].toInt() and 0xFF)
        assertEquals(2, bytes[1].toInt()) // type length
        val hsPayloadLen = bytes[2].toInt() and 0xFF
        assertEquals("Hs", String(bytes, 3, 2, Charsets.US_ASCII))
        val hsPayload = bytes.copyOfRange(5, 5 + hsPayloadLen)
        assertEquals(0x15, hsPayload[0].toInt() and 0xFF) // CH version 1.5

        // Embedded "ac" record inside the Hs payload - both MB and ME set (it's the only record in this inner message).
        val ac = hsPayload.copyOfRange(1, hsPayload.size)
        assertEquals(0xD1, ac[0].toInt() and 0xFF) // MB=1,ME=1,SR=1,TNF=well-known
        assertEquals("ac", String(ac, 3, 2, Charsets.US_ASCII))
        val acPayload = ac.copyOfRange(5, ac.size)
        assertEquals(0x01, acPayload[0].toInt()) // CPS = active
        assertEquals(1, acPayload[1].toInt()) // Carrier Data Reference length
        assertEquals("0", String(acPayload, 2, 1, Charsets.US_ASCII))
        assertEquals(1, acPayload[3].toInt()) // Auxiliary Data Reference Count
        assertEquals(4, acPayload[4].toInt()) // Aux Data Reference length
        assertEquals("mdoc", String(acPayload, 5, 4, Charsets.US_ASCII))

        var offset = 5 + hsPayloadLen

        // Record 2: BLE carrier configuration, MIME type, ID "0".
        assertEquals(0x1A, bytes[offset].toInt() and 0xFF) // MB=0,ME=0,SR=1,IL=1,TNF=MIME(2)
        val carrierTypeLen = bytes[offset + 1].toInt() and 0xFF
        val carrierPayloadLen = bytes[offset + 2].toInt() and 0xFF
        val carrierIdLen = bytes[offset + 3].toInt() and 0xFF
        val carrierTypeStart = offset + 4
        assertEquals(
            "application/vnd.bluetooth.le.oob",
            String(bytes, carrierTypeStart, carrierTypeLen, Charsets.US_ASCII),
        )
        val carrierIdStart = carrierTypeStart + carrierTypeLen
        assertEquals("0", String(bytes, carrierIdStart, carrierIdLen, Charsets.US_ASCII))
        val carrierPayloadStart = carrierIdStart + carrierIdLen
        val carrierPayload = bytes.copyOfRange(carrierPayloadStart, carrierPayloadStart + carrierPayloadLen)
        // AD structures: LE Device Address (0x1B, 7 bytes) then LE Role (0x1C, 1 byte).
        assertEquals(0x1B, carrierPayload[1].toInt() and 0xFF)
        assertEquals(0x1C, carrierPayload[10].toInt() and 0xFF)

        offset = carrierPayloadStart + carrierPayloadLen

        // Record 3: device engagement, external type, ID "mdoc", last record (ME=1).
        assertEquals(0x5C, bytes[offset].toInt() and 0xFF) // MB=0,ME=1,SR=1,IL=1,TNF=external(4)
        val deTypeLen = bytes[offset + 1].toInt() and 0xFF
        val dePayloadLen = bytes[offset + 2].toInt() and 0xFF
        val deIdLen = bytes[offset + 3].toInt() and 0xFF
        val deTypeStart = offset + 4
        assertEquals(
            "iso.org:18013:deviceengagement",
            String(bytes, deTypeStart, deTypeLen, Charsets.US_ASCII),
        )
        val deIdStart = deTypeStart + deTypeLen
        assertEquals("mdoc", String(bytes, deIdStart, deIdLen, Charsets.US_ASCII))
        val dePayloadStart = deIdStart + deIdLen
        val dePayload = bytes.copyOfRange(dePayloadStart, dePayloadStart + dePayloadLen)
        assertArrayEquals(hex(d33DeviceEngagementHex), dePayload)
        assertEquals(bytes.size, dePayloadStart + dePayloadLen)
    }

    @Test
    fun build_ourOwnDeviceEngagementBytes_roundTripsUnderTheSameStructureAsTheOfficialVector() {
        // Reuse the official vector's own DeviceEngagement bytes as our engagement payload -
        // isolates this test to NfcHandoverSelect's own framing, independent of DeviceEngagement.create().
        val deBytes = hex(d33DeviceEngagementHex)

        val message = NfcHandoverSelect.build(deBytes, NfcHandoverSelect.LeRole.BOTH_CENTRAL_PREFERRED)

        assertEquals(0x91, message[0].toInt() and 0xFF)
        assertEquals("Hs", String(message, 3, 2, Charsets.US_ASCII))
        val hsPayloadLen = message[2].toInt() and 0xFF
        var offset = 5 + hsPayloadLen

        assertEquals(0x1A, message[offset].toInt() and 0xFF)
        val carrierTypeLen = message[offset + 1].toInt() and 0xFF
        val carrierPayloadLen = message[offset + 2].toInt() and 0xFF
        val carrierIdLen = message[offset + 3].toInt() and 0xFF
        val carrierTypeStart = offset + 4
        assertEquals(
            "application/vnd.bluetooth.le.oob",
            String(message, carrierTypeStart, carrierTypeLen, Charsets.US_ASCII),
        )
        val carrierPayload = message.copyOfRange(
            carrierTypeStart + carrierTypeLen + carrierIdLen,
            carrierTypeStart + carrierTypeLen + carrierIdLen + carrierPayloadLen,
        )
        // Single AD structure: LE Role, value = both-central-preferred (0x03).
        assertEquals(2, carrierPayload[0].toInt())
        assertEquals(0x1C, carrierPayload[1].toInt() and 0xFF)
        assertEquals(NfcHandoverSelect.LeRole.BOTH_CENTRAL_PREFERRED.value, carrierPayload[2].toInt())

        offset = carrierTypeStart + carrierTypeLen + carrierIdLen + carrierPayloadLen
        assertEquals(0x5C, message[offset].toInt() and 0xFF)
        val deTypeLen = message[offset + 1].toInt() and 0xFF
        val dePayloadLen = message[offset + 2].toInt() and 0xFF
        val deIdLen = message[offset + 3].toInt() and 0xFF
        val deTypeStart = offset + 4
        assertEquals(
            "iso.org:18013:deviceengagement",
            String(message, deTypeStart, deTypeLen, Charsets.US_ASCII),
        )
        val dePayloadStart = deTypeStart + deTypeLen + deIdLen
        assertArrayEquals(deBytes, message.copyOfRange(dePayloadStart, dePayloadStart + dePayloadLen))
        assertEquals(message.size, dePayloadStart + dePayloadLen)
    }

    @Test
    fun build_fromEngagement_derivesLeRoleFromWhichBleModesAreOffered() {
        val both = DeviceEngagement.create(supportsCentralClientMode = true, supportsPeripheralServerMode = true)
        val centralOnly = DeviceEngagement.create(supportsCentralClientMode = true, supportsPeripheralServerMode = false)
        val peripheralOnly = DeviceEngagement.create(supportsCentralClientMode = false, supportsPeripheralServerMode = true)

        assertEquals(NfcHandoverSelect.LeRole.BOTH_CENTRAL_PREFERRED, leRoleOf(NfcHandoverSelect.build(both)))
        assertEquals(NfcHandoverSelect.LeRole.CENTRAL_ONLY, leRoleOf(NfcHandoverSelect.build(centralOnly)))
        assertEquals(NfcHandoverSelect.LeRole.PERIPHERAL_ONLY, leRoleOf(NfcHandoverSelect.build(peripheralOnly)))
    }

    @Test
    fun build_fromEngagement_sendsOnlyTheUuidMatchingTheRoleTheReaderIsToldToPrefer() {
        // Both modes offered -> LE Role hints central-preferred, so the AD
        // must carry centralClientModeUuid, NOT peripheralServerModeUuid -
        // sending both/the wrong one leaves a reader that honors the hint
        // advertising under a UUID nobody is scanning for.
        val both = DeviceEngagement.create(supportsCentralClientMode = true, supportsPeripheralServerMode = true)
        assertEquals(listOf(both.centralClientModeUuid), uuidsOf(NfcHandoverSelect.build(both)))

        val peripheralOnly = DeviceEngagement.create(supportsCentralClientMode = false, supportsPeripheralServerMode = true)
        assertEquals(listOf(peripheralOnly.peripheralServerModeUuid), uuidsOf(NfcHandoverSelect.build(peripheralOnly)))
    }

    /** Extract the Complete List of 128-bit Service UUIDs (0x07) AD, if present, from a built message. */
    private fun uuidsOf(message: ByteArray): List<UUID> {
        val hsPayloadLen = message[2].toInt() and 0xFF
        val offset = 5 + hsPayloadLen
        val carrierTypeLen = message[offset + 1].toInt() and 0xFF
        val carrierIdLen = message[offset + 3].toInt() and 0xFF
        val carrierPayloadStart = offset + 4 + carrierTypeLen + carrierIdLen
        // AD1 (LE Role) is always length=2 + the length byte itself = 3 bytes.
        val ad2Start = carrierPayloadStart + 3
        if (ad2Start >= message.size || message[ad2Start + 1].toInt() and 0xFF != 0x07) return emptyList()
        val ad2Len = message[ad2Start].toInt() and 0xFF
        val uuidBytesTotal = ad2Len - 1
        val data = message.copyOfRange(ad2Start + 2, ad2Start + 2 + uuidBytesTotal)
        return (0 until uuidBytesTotal / 16).map { i ->
            val reversed = data.copyOfRange(i * 16, i * 16 + 16).reversed().toByteArray()
            val msb = (0 until 8).fold(0L) { acc, b -> (acc shl 8) or (reversed[b].toLong() and 0xFF) }
            val lsb = (0 until 8).fold(0L) { acc, b -> (acc shl 8) or (reversed[8 + b].toLong() and 0xFF) }
            UUID(msb, lsb)
        }
    }

    /** Extract the LE Role AD value from a built Handover Select message's fixed-offset carrier record. */
    private fun leRoleOf(message: ByteArray): NfcHandoverSelect.LeRole {
        val hsPayloadLen = message[2].toInt() and 0xFF
        val carrierPayloadStart = 5 + hsPayloadLen + 4 // header(4) of the MIME carrier record with a 32-byte type + 1-byte id
        val carrierTypeLen = message[5 + hsPayloadLen + 1].toInt() and 0xFF
        val carrierIdLen = message[5 + hsPayloadLen + 3].toInt() and 0xFF
        val roleValue = message[carrierPayloadStart + carrierTypeLen + carrierIdLen + 2].toInt()
        return NfcHandoverSelect.LeRole.entries.first { it.value == roleValue }
    }

    @Test
    fun build_withUuids_includesCompleteListOf128BitServiceUuidsAdInLittleEndianOrder() {
        val deBytes = hex(d33DeviceEngagementHex)
        // A UUID with a distinct byte in every position, so any byte-order
        // mistake (reversal, half-swap) shows up as a mismatch rather than
        // coincidentally passing (e.g. a palindrome-like UUID wouldn't).
        val uuid = UUID.fromString("01020304-0506-0708-090a-0b0c0d0e0f10")

        val message = NfcHandoverSelect.build(deBytes, NfcHandoverSelect.LeRole.CENTRAL_ONLY, listOf(uuid))

        val hsPayloadLen = message[2].toInt() and 0xFF
        val offset = 5 + hsPayloadLen
        val carrierTypeLen = message[offset + 1].toInt() and 0xFF
        val carrierIdLen = message[offset + 3].toInt() and 0xFF
        val carrierPayloadStart = offset + 4 + carrierTypeLen + carrierIdLen
        val carrierPayload = message.copyOfRange(carrierPayloadStart, carrierPayloadStart + 21)

        // AD 1: LE Role (unaffected by the new AD following it).
        assertEquals(2, carrierPayload[0].toInt())
        assertEquals(0x1C, carrierPayload[1].toInt() and 0xFF)
        assertEquals(NfcHandoverSelect.LeRole.CENTRAL_ONLY.value, carrierPayload[2].toInt())

        // AD 2: Complete List of 128-bit Service UUIDs (0x07), length = type(1) + 16 bytes.
        assertEquals(17, carrierPayload[3].toInt())
        assertEquals(0x07, carrierPayload[4].toInt() and 0xFF)
        val uuidBytes = carrierPayload.copyOfRange(5, 21)
        // Bluetooth OOB AD data is little-endian - the reverse of the
        // big-endian byte order RFC 4122 (and DeviceEngagement's BleOptions
        // CBOR) uses for the same UUID.
        val expectedLittleEndian = hex("100f0e0d0c0b0a090807060504030201")
        assertArrayEquals(expectedLittleEndian, uuidBytes)
    }

    @Test
    fun build_neitherBleMode_throws() {
        try {
            NfcHandoverSelect.build(
                DeviceEngagement.Engagement(
                    deviceEngagementBytes = ByteArray(0),
                    mdocUri = "mdoc:",
                    publicKey = DeviceEngagement.create().publicKey,
                    privateKey = DeviceEngagement.create().privateKey,
                    eDeviceKeyBytes = ByteArray(0),
                    peripheralServerModeUuid = null,
                    centralClientModeUuid = null,
                ),
            )
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}
