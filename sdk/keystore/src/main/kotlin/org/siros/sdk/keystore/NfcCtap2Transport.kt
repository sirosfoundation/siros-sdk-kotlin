package org.siros.sdk.keystore

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import java.io.IOException

/**
 * NFC CTAP2 transport for FIDO2 authenticators (e.g. YubiKey) presented as
 * an ISO-DEP (ISO 14443-4) tag.
 *
 * Implements the SDK-level [Ctap2TransportProvider] - same division of
 * responsibility as [UsbCtap2Transport]: all previewSign CBOR
 * request-building and response-parsing lives in Rust
 * (`siros-wscd-manager`'s `preview_sign_protocol` module). This class only
 * owns the physical transport below that - CTAP2's NFC framing (FIDO
 * CTAP2.1 §8.2.9): select the FIDO applet by AID, then wrap each raw CTAP2
 * command (leading command byte + CBOR params) in an extended-length ISO
 * 7816-4 APDU and return the response with its trailing SW1SW2 stripped.
 *
 * Unlike USB's CTAPHID (channel handshake + KEEPALIVE polling while waiting
 * for a physical touch), NFC has no separate "user presence" signal - the
 * user tapping/holding the authenticator to the reader IS presence, so
 * there's no keepalive loop to handle, just a single blocking APDU
 * exchange per command. The user must keep the authenticator in the NFC
 * field for the whole session (every [send] call), not just the initial
 * tap - lifting it early surfaces as [Ctap2TransportException.DeviceDisconnected]
 * via [TagLostException], which [Ctap2TransportBridge] already retries
 * once by reconnecting.
 *
 * Takes an [Activity] rather than a plain [android.content.Context] -
 * `NfcAdapter.enableReaderMode` requires one; this is a real Android API
 * constraint, not a design choice, so a host app must supply its current
 * foreground Activity when constructing this transport.
 */
class NfcCtap2Transport(private val activity: Activity) : Ctap2TransportProvider {

    private var isoDep: IsoDep? = null

    companion object {
        private const val TAG = "NfcCtap2Transport"

        // FIDO2 CTAP2 applet AID (FIDO CTAP2.1 §8.2.9.1).
        private val FIDO_AID = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
        )

        private const val SW_SUCCESS = 0x9000
        private const val TAG_WAIT_TIMEOUT_MS = 30_000L
        private const val ISODEP_TIMEOUT_MS = 20_000

        private const val READER_FLAGS =
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
    }

    override suspend fun isAvailable(): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity)
        return adapter != null && adapter.isEnabled
    }

    override suspend fun connect() {
        val adapter = NfcAdapter.getDefaultAdapter(activity)
            ?: throw Ctap2TransportException.NotAvailable()
        if (!adapter.isEnabled) throw Ctap2TransportException.NotAvailable()

        val tagDeferred = CompletableDeferred<Tag>()
        adapter.enableReaderMode(
            activity,
            { tag -> tagDeferred.complete(tag) },
            READER_FLAGS,
            null,
        )

        val tag = try {
            Log.i(TAG, "Waiting for NFC tap - present the security key")
            withTimeout(TAG_WAIT_TIMEOUT_MS) { tagDeferred.await() }
        } catch (e: TimeoutCancellationException) {
            adapter.disableReaderMode(activity)
            throw Ctap2TransportException.NotAvailable()
        }

        val tech = IsoDep.get(tag) ?: run {
            adapter.disableReaderMode(activity)
            throw Ctap2TransportException.ConnectionFailed("Tag does not support ISO-DEP")
        }

        try {
            tech.timeout = ISODEP_TIMEOUT_MS
            tech.connect()
            selectFidoApplet(tech)
        } catch (e: Exception) {
            runCatching { tech.close() }
            adapter.disableReaderMode(activity)
            throw Ctap2TransportException.ConnectionFailed(e.message ?: "NFC connect failed")
        }

        isoDep = tech
        Log.i(TAG, "FIDO2 applet selected over NFC")
    }

    override suspend fun disconnect() {
        runCatching { isoDep?.close() }
        isoDep = null
        NfcAdapter.getDefaultAdapter(activity)?.disableReaderMode(activity)
    }

    /**
     * Send a raw CTAP2 command (already CBOR-encoded with its leading
     * command byte, built by Rust's `preview_sign_protocol` module) and
     * return the raw response bytes exactly as received (leading status
     * byte + CBOR body) - same shape [UsbCtap2Transport.send] returns. No
     * CBOR knowledge here - Rust does all encoding/decoding on both sides.
     */
    override suspend fun send(command: ByteArray): ByteArray {
        val tech = isoDep ?: throw Ctap2TransportException.DeviceDisconnected()
        Log.i(TAG, "CTAP2 command (${command.size}B): ${command.toHex()}")
        val response = try {
            tech.transceive(buildApdu(command))
        } catch (e: TagLostException) {
            isoDep = null
            throw Ctap2TransportException.DeviceDisconnected()
        } catch (e: IOException) {
            throw Ctap2TransportException.DeviceDisconnected()
        }
        val unwrapped = unwrapApduResponse(response)
        Log.i(TAG, "CTAP2 response (${unwrapped.size}B): ${unwrapped.toHex()}")
        return unwrapped
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /** ISO 7816-4 SELECT (by name) for the FIDO2 applet AID. */
    private fun selectFidoApplet(tech: IsoDep) {
        val selectApdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, FIDO_AID.size.toByte()) +
            FIDO_AID + byteArrayOf(0x00)
        val response = tech.transceive(selectApdu)
        val sw = statusWord(response)
        if (sw != SW_SUCCESS) {
            throw Ctap2TransportException.ConnectionFailed(
                "SELECT FIDO applet failed: SW=0x${sw.toString(16)}",
            )
        }
    }

    /**
     * Wrap a raw CTAP2 command in a CTAP2-over-NFC APDU (FIDO CTAP2.1
     * §8.2.9.2): CLA=0x80, INS=0x10, P1=P2=0x00, extended-length Lc/data,
     * extended Le=0x0000 (accept up to the protocol maximum back).
     */
    private fun buildApdu(command: ByteArray): ByteArray {
        val lc = command.size
        val header = byteArrayOf(0x80.toByte(), 0x10, 0x00, 0x00)
        val lcBytes = byteArrayOf(0x00, ((lc shr 8) and 0xFF).toByte(), (lc and 0xFF).toByte())
        val le = byteArrayOf(0x00, 0x00)
        return header + lcBytes + command + le
    }

    private fun unwrapApduResponse(response: ByteArray): ByteArray {
        val sw = statusWord(response)
        if (sw != SW_SUCCESS) {
            throw Ctap2TransportException.InvalidResponse("APDU status 0x${sw.toString(16)}")
        }
        return response.copyOfRange(0, response.size - 2)
    }

    private fun statusWord(response: ByteArray): Int {
        if (response.size < 2) {
            throw Ctap2TransportException.InvalidResponse("APDU response too short")
        }
        return ((response[response.size - 2].toInt() and 0xFF) shl 8) or
            (response[response.size - 1].toInt() and 0xFF)
    }
}
