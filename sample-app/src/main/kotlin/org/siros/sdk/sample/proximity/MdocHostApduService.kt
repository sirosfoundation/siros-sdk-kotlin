// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.proximity

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import timber.log.Timber

/**
 * ISO 18013-5 §9.2 NFC static handover: emulates an NFC Forum Type 4 Tag
 * serving a Handover Select NDEF message (built by
 * `NfcHandoverSelect.build`) from the currently-active
 * [ActiveEngagement.handoverSelectBytes]. Implements just enough of ISO
 * 7816-4/NFC Forum Type 4 Tag Operation to serve a single, read-only NDEF
 * file: SELECT (NDEF application AID, then Capability Container, then NDEF
 * file) and READ BINARY. No Negotiated Handover, no write support - this
 * document only requires Static Handover (§9.2.1).
 *
 * Real hardware validation (a physical reader tapping a physical Android
 * device) is still pending - see the proximity presentation plan's
 * feasibility notes on needing a reference mdoc reader.
 */
class MdocHostApduService : HostApduService() {

    companion object {
        private val SW_OK = byteArrayOf(0x90.toByte(), 0x00)
        private val SW_FILE_NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())
        private val SW_INS_NOT_SUPPORTED = byteArrayOf(0x6D, 0x00)

        private val NDEF_AID = hexToBytes("D2760000850101")
        private val CC_FILE_ID = byteArrayOf(0xE1.toByte(), 0x03)
        private val NDEF_FILE_ID = byteArrayOf(0xE1.toByte(), 0x04)

        private const val INS_SELECT = 0xA4.toByte()
        private const val INS_READ_BINARY = 0xB0.toByte()

        private fun hexToBytes(s: String): ByteArray =
            ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        /** Capability Container file content, per NFC Forum Type 4 Tag §5.1 - see [ccFile]'s call site. */
        private fun ccFile(ndefMaxSize: Int): ByteArray {
            return byteArrayOf(
                0x00, 0x0F, // CCLEN = 15 bytes total
                0x20, // Mapping version 2.0
                0xFF.toByte(), 0xFF.toByte(), // MLe (max R-APDU data size)
                0xFF.toByte(), 0xFF.toByte(), // MLc (max C-APDU data size)
                0x04, 0x06, // NDEF File Control TLV: tag=04, length=6
                NDEF_FILE_ID[0], NDEF_FILE_ID[1],
                (ndefMaxSize shr 8).toByte(), (ndefMaxSize and 0xFF).toByte(),
                0x00, // read access: no security
                0xFF.toByte(), // write access: not writable
            )
        }
    }

    private enum class SelectedFile { NONE, CC, NDEF }

    private var selectedFile = SelectedFile.NONE

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        val apdu = commandApdu ?: return SW_INS_NOT_SUPPORTED
        if (apdu.size < 4) return SW_INS_NOT_SUPPORTED

        val ins = apdu[1]
        return when (ins) {
            INS_SELECT -> handleSelect(apdu)
            INS_READ_BINARY -> handleReadBinary(apdu)
            else -> SW_INS_NOT_SUPPORTED
        }
    }

    private fun handleSelect(apdu: ByteArray): ByteArray {
        if (apdu.size < 5) return SW_INS_NOT_SUPPORTED
        val p1 = apdu[2]
        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) return SW_INS_NOT_SUPPORTED
        val data = apdu.copyOfRange(5, 5 + lc)

        return when {
            p1 == 0x04.toByte() && data.contentEquals(NDEF_AID) -> {
                selectedFile = SelectedFile.NONE
                SW_OK
            }
            p1 == 0x00.toByte() && data.contentEquals(CC_FILE_ID) -> {
                selectedFile = SelectedFile.CC
                SW_OK
            }
            p1 == 0x00.toByte() && data.contentEquals(NDEF_FILE_ID) -> {
                selectedFile = SelectedFile.NDEF
                SW_OK
            }
            else -> {
                Timber.w("MdocHostApduService: SELECT for unknown file")
                SW_FILE_NOT_FOUND
            }
        }
    }

    private fun handleReadBinary(apdu: ByteArray): ByteArray {
        val offset = ((apdu[2].toInt() and 0xFF) shl 8) or (apdu[3].toInt() and 0xFF)
        val le = if (apdu.size > 4) apdu[4].toInt() and 0xFF else 0
        val length = if (le == 0) 256 else le

        val fileContent = when (selectedFile) {
            SelectedFile.CC -> {
                val handoverSelect = ActiveEngagement.handoverSelectBytes
                ccFile(ndefMaxSize = 2 + (handoverSelect?.size ?: 0))
            }
            SelectedFile.NDEF -> {
                val handoverSelect = ActiveEngagement.handoverSelectBytes ?: return SW_FILE_NOT_FOUND
                // NDEF file = 2-byte big-endian NLEN + the NDEF message itself.
                val nlen = byteArrayOf((handoverSelect.size shr 8).toByte(), (handoverSelect.size and 0xFF).toByte())
                nlen + handoverSelect
            }
            SelectedFile.NONE -> return SW_FILE_NOT_FOUND
        }

        if (offset >= fileContent.size) return SW_FILE_NOT_FOUND
        val end = minOf(offset + length, fileContent.size)
        return fileContent.copyOfRange(offset, end) + SW_OK
    }

    override fun onDeactivated(reason: Int) {
        selectedFile = SelectedFile.NONE
        Timber.d("MdocHostApduService: deactivated (reason=$reason)")
    }
}
