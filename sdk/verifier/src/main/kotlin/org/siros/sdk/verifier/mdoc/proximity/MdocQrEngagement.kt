// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import java.util.UUID

/** Transport-neutral engagement inputs shared by QR and NFC static handover. */
interface MdocEngagement {
    val deviceEngagementBytes: ByteArray
    val eDeviceKeyBytes: ByteArray
    val handoverCbor: ByteArray
    val ble: BleDeviceRetrievalMethod?
}

/**
 * The verifier-side, transport-neutral contents of an ISO 18013-5 `mdoc:` QR
 * engagement.
 *
 * The byte arrays are the exact bytes received, never re-encoded. They can be
 * used directly when constructing the proximity session transcript and when
 * computing the BLE `Ident` characteristic value.
 */
data class MdocQrEngagement(
    /** The original, untagged `DeviceEngagement` CBOR bytes. */
    override val deviceEngagementBytes: ByteArray,
    /** The exact tag-24-wrapped `EDeviceKeyBytes`, including its original encoding. */
    override val eDeviceKeyBytes: ByteArray,
    /** `QRHandover = null`, encoded as the single CBOR byte `0xf6`. */
    val qrHandover: ByteArray,
    /** The sole BLE retrieval method, or null when the engagement offers none. */
    override val ble: BleDeviceRetrievalMethod?,
) : MdocEngagement {
    override val handoverCbor: ByteArray
        get() = qrHandover
}

/** Validated ISO 18013-5 `BleOptions` and their discovery UUIDs. */
data class BleDeviceRetrievalMethod(
    val supportsPeripheralServerMode: Boolean,
    val supportsCentralClientMode: Boolean,
    /** Required iff [supportsPeripheralServerMode] is true. */
    val peripheralServerModeUuid: UUID?,
    /** Required iff [supportsCentralClientMode] is true. */
    val centralClientModeUuid: UUID?,
)

/** The QR engagement is outside the supported ISO 18013-5 profile or malformed. */
class MdocEngagementParseException internal constructor(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)
