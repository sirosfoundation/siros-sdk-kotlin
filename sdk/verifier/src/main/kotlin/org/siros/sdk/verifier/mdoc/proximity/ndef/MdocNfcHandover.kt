// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef

import org.siros.sdk.verifier.mdoc.proximity.BleDeviceRetrievalMethod
import org.siros.sdk.verifier.mdoc.proximity.MdocEngagement
import org.siros.sdk.verifier.mdoc.proximity.MdocQrEngagement

/**
 * A validated ISO 18013-5 NFC static handover and its exact transcript inputs.
 *
 * [handoverSelectBytes] is the complete NDEF Handover Select message as
 * received. [handoverCbor] is the canonical `NFCHandover` value
 * `[HandoverSelectBytes, null]`; neither value is derived from a re-encoded
 * NDEF message or DeviceEngagement.
 */
data class MdocNfcHandover(
    /** The complete original NDEF Handover Select message. */
    val handoverSelectBytes: ByteArray,
    /** Canonical CBOR encoding of `[HandoverSelectBytes, null]`. */
    override val handoverCbor: ByteArray,
    /** The strictly validated DeviceEngagement auxiliary record. */
    val engagement: MdocQrEngagement,
    /**
     * BLE metadata usable by the verifier-side transport selector, or null
     * when the handover does not contain enough information to select BLE.
     */
    override val ble: BleDeviceRetrievalMethod?,
) : MdocEngagement {
    /** The exact raw DeviceEngagement bytes from the auxiliary record. */
    override val deviceEngagementBytes: ByteArray
        get() = engagement.deviceEngagementBytes

    override val eDeviceKeyBytes: ByteArray
        get() = engagement.eDeviceKeyBytes

    /** False for incomplete/address-only BLE metadata, including Annex D.3.3. */
    val bleSupported: Boolean
        get() = ble != null
}

/** The NFC static handover is malformed, unsupported, or internally inconsistent. */
class MdocNfcHandoverParseException internal constructor(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)
