// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import java.io.ByteArrayOutputStream

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
     * Device Address (0x1B) is omitted: it's merely "recommended" and Android
     * has no public API to read the local BLE MAC address (deprecated for
     * privacy since API 23), so the reader is expected to connect using the
     * UUID(s) embedded in the `DeviceEngagement` CBOR itself.
     */
    fun build(engagement: DeviceEngagement.Engagement): ByteArray {
        val leRole = when {
            engagement.centralClientModeUuid != null && engagement.peripheralServerModeUuid != null ->
                LeRole.BOTH_CENTRAL_PREFERRED
            engagement.centralClientModeUuid != null -> LeRole.CENTRAL_ONLY
            engagement.peripheralServerModeUuid != null -> LeRole.PERIPHERAL_ONLY
            else -> throw IllegalArgumentException("engagement offers no BLE retrieval method")
        }
        return build(engagement.deviceEngagementBytes, leRole)
    }

    /** Lower-level overload taking the LE Role explicitly - used by tests. */
    fun build(deviceEngagementBytes: ByteArray, leRole: LeRole): ByteArray {
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
            payload = bleOobPayload(leRole),
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
     * each `length(1) + type(1) + data(length-1)`. Only LE Role is included -
     * see [build]'s doc comment for why LE Device Address is omitted.
     */
    private fun bleOobPayload(leRole: LeRole): ByteArray {
        return ByteArrayOutputStream().apply {
            write(2) // AD length = type(1) + data(1)
            write(AD_TYPE_LE_ROLE)
            write(leRole.value)
        }.toByteArray()
    }

    private fun ndefRecord(
        tnf: Int,
        type: ByteArray,
        id: ByteArray?,
        payload: ByteArray,
        messageBegin: Boolean,
        messageEnd: Boolean,
    ): ByteArray {
        require(payload.size < 256) { "NDEF short record payload must be < 256 bytes" }
        var header = tnf
        if (messageBegin) header = header or NDEF_MB
        if (messageEnd) header = header or NDEF_ME
        header = header or NDEF_SR
        if (id != null) header = header or NDEF_IL

        return ByteArrayOutputStream().apply {
            write(header)
            write(type.size)
            write(payload.size)
            if (id != null) write(id.size)
            write(type)
            if (id != null) write(id)
            write(payload)
        }.toByteArray()
    }
}
