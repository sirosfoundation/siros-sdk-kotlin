// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject

/**
 * ISO 18013-5 §9.1.5.1 proximity session transcript:
 * ```
 * SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ]
 * Handover = QRHandover / NFCHandover
 * QRHandover = null
 * NFCHandover = [ bstr, bstr / null ]   ; [Handover Select msg, Handover Request msg (null for Static Handover)]
 * ```
 *
 * A third, distinct session-transcript variant alongside
 * `MdocDeviceResponseBuilder`'s existing `OpenID4VPHandover` (redirect flow)
 * and `OpenID4VPDCAPIHandover` (DC API) transcripts - this one is for real
 * ISO 18013-5 proximity (BLE) presentation, not OpenID4VP.
 *
 * Returns the bare (untagged) `SessionTranscript` array bytes, matching
 * `MdocDeviceResponseBuilder.buildForProximity`'s expected input (which
 * decodes and re-embeds them into `DeviceAuthentication` directly, per the
 * spec's `DeviceAuthentication = [..., SessionTranscript, ...]` - note:
 * `SessionTranscript`, not the tag-24-wrapped `SessionTranscriptBytes`).
 * [ProximitySessionCrypto] performs its own tag-24 wrap when it needs the
 * tag-24-wrapped `SessionTranscriptBytes` form for the HKDF salt - see its
 * doc comment.
 */
object ProximitySessionTranscript {

    /**
     * @param deviceEngagementBytes raw (untagged) `DeviceEngagement` CBOR, as produced by [DeviceEngagement.create].
     * @param eReaderKeyBytes the incoming `SessionEstablishment` message's `eReaderKey` field
     *   (already `#6.24`-tagged `COSE_Key`), as re-encoded by [ProximitySessionMessages.parseSessionEstablishment]
     *   from the parsed CBOR value - not rebuilt from separately-derived key material, so this
     *   matches what the reader sent for any canonically-CBOR-encoded input. A reader using a
     *   non-canonical encoding (e.g. indefinite-length or non-minimal integers) could in principle
     *   produce different bytes here than what was on the wire, which would derive different
     *   session keys - not expected in practice, but worth knowing if interop debugging ever points here.
     * @param handoverSelectMessageBytes the NDEF Handover Select message bytes
     *   ([NfcHandoverSelect.build]'s output) if device engagement happened via NFC static
     *   handover; null if via QR.
     */
    fun build(
        deviceEngagementBytes: ByteArray,
        eReaderKeyBytes: ByteArray,
        handoverSelectMessageBytes: ByteArray?,
    ): ByteArray {
        val taggedDeviceEngagement = CBORObject.FromObjectAndTag(deviceEngagementBytes, 24)
        val eReaderKey = CBORObject.DecodeFromBytes(eReaderKeyBytes)

        val handover = if (handoverSelectMessageBytes == null) {
            CBORObject.Null
        } else {
            val nfcHandover = CBORObject.NewArray()
            nfcHandover.Add(CBORObject.FromObject(handoverSelectMessageBytes))
            nfcHandover.Add(CBORObject.Null)
            nfcHandover
        }

        val transcript = CBORObject.NewArray()
        transcript.Add(taggedDeviceEngagement)
        transcript.Add(eReaderKey)
        transcript.Add(handover)
        return transcript.EncodeToBytes()
    }
}
