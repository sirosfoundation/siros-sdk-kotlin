// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import java.io.ByteArrayOutputStream
import java.util.UUID

/**
 * ISO 18013-5 §9.2/§11.1.2 NFC Static Handover: builds the Handover Select
 * NDEF message an mdoc (acting as an NFC Forum Type 4 Tag, per §9.2.1) serves
 * to an mdoc reader, wrapping a [DeviceEngagement.Engagement] for BLE data
 * retrieval.
 *
 * Byte layout verified by hand against the official worked example in Annex
 * D.3.3 of the ISO/IEC 18013-5 second-edition CD ballot-resolution draft
 * (`91020f487315d10209...`), which decodes to exactly the three-record NDEF
 * message this builder produces: an "Hs" (Handover Select) record wrapping a
 * single "ac" (Alternative Carrier) record, a MIME carrier-configuration
 * record (`application/vnd.bluetooth.le.oob`), and an external-type
 * auxiliary record (`iso.org:18013:deviceengagement`) carrying the
 * `DeviceEngagement` CBOR bytes verbatim.
 */
object NfcHandoverSelect {

    // NDEF record header bit positions (NFC Forum NDEF Technical
    // Specification 1.0 §3.2).
    private const val NDEF_MB = 0x80
    private const val NDEF_ME = 0x40
    private const val NDEF_SR = 0x10
    private const val NDEF_IL = 0x08
    private const val TNF_WELL_KNOWN = 0x01
    private const val TNF_MIME = 0x02
    private const val TNF_EXTERNAL = 0x04

    /** Connection Handover (CH) Technical Specification version 1.5, per §9.2.1. */
    private const val HANDOVER_VERSION_1_5 = 0x15

    /** Carrier Power State "active", per NFC Forum CH 1.5 §5.1 (ac record). */
    private const val CPS_ACTIVE = 0x01

    private const val CARRIER_DATA_REFERENCE = "0"
    private const val AUX_DATA_REFERENCE = "mdoc"
    private const val BLE_OOB_MIME_TYPE = "application/vnd.bluetooth.le.oob"
    private const val DEVICE_ENGAGEMENT_EXTERNAL_TYPE = "iso.org:18013:deviceengagement"

    // Bluetooth Supplement to the Core Specification AD types (§11.1.2).
    private const val AD_TYPE_LE_ROLE = 0x1C
    private const val AD_TYPE_COMPLETE_128_BIT_SERVICE_UUIDS = 0x07

    /** Bluetooth Supplement to the Core Specification LE Role AD (0x1C) values. */
    enum class LeRole(val value: Int) {
        PERIPHERAL_ONLY(0x00),
        CENTRAL_ONLY(0x01),
        /** Both roles supported, peripheral preferred for connection establishment. */
        BOTH_PERIPHERAL_PREFERRED(0x02),
        /** Both roles supported, central preferred - matches §11.1.3.1's guidance that a
         *  reader "should select the mdoc central client mode" when both are offered. */
        BOTH_CENTRAL_PREFERRED(0x03),
    }

    /**
     * Build the Handover Select NDEF message for [engagement].
     *
     * The LE Role advertised is derived from which BLE modes [engagement]
     * offers - matching the mandatory LE Role (0x1C) AD type (§11.1.2). LE
     * Device Address (0x1B) is omitted: it's merely "recommended", and
     * Android has no public API to read the local BLE MAC address
     * (deprecated for privacy since API 23) - but §11.1.2 is explicit that
     * LE Device Address only shortens the connection process "COMPARED TO
     * USING THE UUID to identify the correct device to connect to", i.e. the
     * UUID remains how a reader is meant to find the right device when no
     * address is given. That UUID must therefore appear in this record's own
     * Complete List of 128-bit Service UUIDs (0x07) AD - relying solely on
     * the separate DeviceEngagement CBOR aux record leaves a reader with no
     * AD-level UUID to scan for at all, confirmed live: a real mdoc reader
     * reported receiving our engagement via NFC but never finding any UUID
     * to connect to. (Annex D.3.3's own worked example omits 0x07, but only
     * because IT includes 0x1B - not a precedent for omitting both.)
     *
     * Only ONE UUID goes in that AD, matching §11.1.2's own wording for
     * Static Handover: "the mdoc shall send one UUID... to be used for mdoc
     * central client mode or mdoc peripheral server mode AS APPROPRIATE".
     * The AD has no way to label which of two UUIDs belongs to which role -
     * sending both invites a reader to pick the wrong one for whichever role
     * it actually plays (e.g. advertise under the peripheral UUID while we
     * scan for the central one), a real deadlock confirmed live. The one
     * UUID sent matches [leRole]'s own preference: the reader is being told
     * (via LE Role) which mode to prefer, so it's also the mode whose UUID
     * it needs from this AD to act on that preference. A reader that
     * instead falls back to the other mode already has that mode's own UUID
     * available from the DeviceEngagement CBOR's own keyed fields (10/11).
     */
    fun build(engagement: DeviceEngagement.Engagement): ByteArray {
        val leRole = when {
            engagement.centralClientModeUuid != null && engagement.peripheralServerModeUuid != null ->
                LeRole.BOTH_CENTRAL_PREFERRED
            engagement.centralClientModeUuid != null -> LeRole.CENTRAL_ONLY
            engagement.peripheralServerModeUuid != null -> LeRole.PERIPHERAL_ONLY
            else -> throw IllegalArgumentException("engagement offers no BLE retrieval method")
        }
        // leRole is only ever PERIPHERAL_ONLY, CENTRAL_ONLY, or
        // BOTH_CENTRAL_PREFERRED here (see the assignment above) - the
        // latter two both mean "the reader should use central client mode",
        // so both map to centralClientModeUuid.
        val preferredUuid = if (leRole == LeRole.PERIPHERAL_ONLY) {
            engagement.peripheralServerModeUuid
        } else {
            engagement.centralClientModeUuid
        }
        return build(engagement.deviceEngagementBytes, leRole, listOfNotNull(preferredUuid))
    }

    /** Lower-level overload taking the LE Role (and optionally the UUID(s) to advertise) explicitly - used by tests. */
    fun build(deviceEngagementBytes: ByteArray, leRole: LeRole, uuids: List<UUID> = emptyList()): ByteArray {
        val acMessage = ndefRecord(
            tnf = TNF_WELL_KNOWN,
            type = "ac".toByteArray(Charsets.US_ASCII),
            id = null,
            payload = alternativeCarrierPayload(),
            messageBegin = true,
            messageEnd = true,
        )
        val hsPayload = ByteArrayOutputStream().apply {
            write(HANDOVER_VERSION_1_5)
            write(acMessage)
        }.toByteArray()

        val hsRecord = ndefRecord(
            tnf = TNF_WELL_KNOWN,
            type = "Hs".toByteArray(Charsets.US_ASCII),
            id = null,
            payload = hsPayload,
            messageBegin = true,
            messageEnd = false,
        )
        val carrierConfigRecord = ndefRecord(
            tnf = TNF_MIME,
            type = BLE_OOB_MIME_TYPE.toByteArray(Charsets.US_ASCII),
            id = CARRIER_DATA_REFERENCE.toByteArray(Charsets.US_ASCII),
            payload = bleOobPayload(leRole, uuids),
            messageBegin = false,
            messageEnd = false,
        )
        val deviceEngagementRecord = ndefRecord(
            tnf = TNF_EXTERNAL,
            type = DEVICE_ENGAGEMENT_EXTERNAL_TYPE.toByteArray(Charsets.US_ASCII),
            id = AUX_DATA_REFERENCE.toByteArray(Charsets.US_ASCII),
            payload = deviceEngagementBytes,
            messageBegin = false,
            messageEnd = true,
        )

        return ByteArrayOutputStream().apply {
            write(hsRecord)
            write(carrierConfigRecord)
            write(deviceEngagementRecord)
        }.toByteArray()
    }

    /**
     * `ac` (Alternative Carrier) record payload, per NFC Forum CH 1.5 §5.1:
     * CPS (1 byte) + Carrier Data Reference (length-prefixed) + Auxiliary
     * Data Reference Count (1 byte) + Auxiliary Data Reference(s)
     * (length-prefixed), referencing the carrier-configuration record by
     * [CARRIER_DATA_REFERENCE] and the device-engagement record by
     * [AUX_DATA_REFERENCE], matching Annex D.3.3's worked example exactly.
     */
    private fun alternativeCarrierPayload(): ByteArray {
        val cdr = CARRIER_DATA_REFERENCE.toByteArray(Charsets.US_ASCII)
        val aux = AUX_DATA_REFERENCE.toByteArray(Charsets.US_ASCII)
        return ByteArrayOutputStream().apply {
            write(CPS_ACTIVE)
            write(cdr.size)
            write(cdr)
            write(1) // Auxiliary Data Reference Count
            write(aux.size)
            write(aux)
        }.toByteArray()
    }

    /**
     * Bluetooth OOB data block (Supplement to the Bluetooth Core
     * Specification, referenced by §11.1.2): a sequence of AD structures,
     * each `length(1) + type(1) + data(length-1)`. LE Role is always
     * present; a Complete List of 128-bit Service UUIDs (0x07) AD is added
     * when [uuids] is non-empty - see [build]'s doc comment for why this is
     * required (not merely "if applicable") given LE Device Address is
     * omitted.
     */
    private fun bleOobPayload(leRole: LeRole, uuids: List<UUID>): ByteArray {
        return ByteArrayOutputStream().apply {
            write(2) // AD length = type(1) + data(1)
            write(AD_TYPE_LE_ROLE)
            write(leRole.value)
            if (uuids.isNotEmpty()) {
                write(1 + 16 * uuids.size) // AD length = type(1) + 16 bytes per UUID
                write(AD_TYPE_COMPLETE_128_BIT_SERVICE_UUIDS)
                for (uuid in uuids) write(littleEndianUuidBytes(uuid))
            }
        }.toByteArray()
    }

    /**
     * Bluetooth's own OOB AD format packs multi-byte values little-endian
     * (per §11.1.2's own note quoting the Bluetooth Core Specification
     * Supplement) - the reverse of the big-endian/RFC 4122 §4.1.2 order
     * `DeviceEngagement`'s BleOptions CBOR uses for the same UUID bytes
     * (see `DeviceEngagement.uuidBytes`), so this can't share that function.
     */
    private fun littleEndianUuidBytes(uuid: UUID): ByteArray {
        val bytes = ByteArray(16)
        val msb = uuid.mostSignificantBits
        val lsb = uuid.leastSignificantBits
        for (i in 0 until 8) bytes[15 - i] = (msb ushr (8 * (7 - i))).toByte()
        for (i in 0 until 8) bytes[7 - i] = (lsb ushr (8 * (7 - i))).toByte()
        return bytes
    }

    private fun ndefRecord(
        tnf: Int,
        type: ByteArray,
        id: ByteArray?,
        payload: ByteArray,
        messageBegin: Boolean,
        messageEnd: Boolean,
    ): ByteArray {
        // NDEF short records (SR) only encode a 1-byte payload length, capping
        // them at 255 bytes - a real DeviceEngagement payload fits comfortably
        // today, but isn't guaranteed to forever (e.g. more retrieval methods
        // or a larger key encoding). Fall back to a normal (non-SR) record
        // with a 4-byte length instead of crashing static handover outright.
        val isShortRecord = payload.size < 256
        var header = tnf
        if (messageBegin) header = header or NDEF_MB
        if (messageEnd) header = header or NDEF_ME
        if (isShortRecord) header = header or NDEF_SR
        if (id != null) header = header or NDEF_IL

        return ByteArrayOutputStream().apply {
            write(header)
            write(type.size)
            if (isShortRecord) {
                write(payload.size)
            } else {
                write((payload.size ushr 24) and 0xFF)
                write((payload.size ushr 16) and 0xFF)
                write((payload.size ushr 8) and 0xFF)
                write(payload.size and 0xFF)
            }
            if (id != null) write(id.size)
            write(type)
            if (id != null) write(id)
            write(payload)
        }.toByteArray()
    }
}
