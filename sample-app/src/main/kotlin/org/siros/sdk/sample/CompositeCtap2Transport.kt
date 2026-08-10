package org.siros.sdk.sample

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import org.siros.sdk.keystore.Ctap2TransportException
import org.siros.sdk.keystore.Ctap2TransportProvider

/**
 * Watches USB and NFC for a FIDO2 authenticator in parallel, so the user
 * doesn't have to pre-select a transport before enrolling/signing - whoever
 * the user actually presents (plugs in or taps) first is used. If both
 * become available close together, [requestChoice] is invoked to ask which
 * one to use instead of silently picking one.
 *
 * [usb]/[nfc]'s own `connect()` already blocks until a device shows up (USB
 * via [UsbCtap2Transport]'s runtime attach-listener, NFC via
 * [NfcCtap2Transport]'s `enableReaderMode`), so this class only needs to
 * race those two waits against each other - no polling of its own.
 */
class CompositeCtap2Transport(
    private val usb: UsbCtap2Transport,
    private val nfc: NfcCtap2Transport,
    private val requestChoice: suspend () -> Fido2TransportMode?,
) : Ctap2TransportProvider {

    private var active: Ctap2TransportProvider? = null

    // Once a race picks a winner, later reconnects (e.g. Ctap2TransportBridge's
    // catch-disconnect-reconnect-retry-once on a transient error - see that
    // class's doc comment) must reconnect to the SAME transport, not re-race
    // from scratch. A multi-step CTAP2 ceremony (ClientPin's key-agreement +
    // token exchange, then MakeCredential) spans several send() calls that
    // all need one continuous physical session; silently switching from NFC
    // to USB (or back) partway through corrupts that ceremony rather than
    // recovering it - confirmed on real hardware: an NFC tag briefly losing
    // contact re-raced and ping-ponged between transports mid-enrollment,
    // and the enrollment never completed.
    private var stickyMode: Fido2TransportMode? = null

    companion object {
        // Once one transport succeeds, how long to give the other a chance
        // to ALSO succeed before deciding this wasn't actually ambiguous -
        // catches "USB already plugged in AND the user also taps NFC within
        // about the same moment," not every case where the second transport
        // simply hasn't found a device yet (which can take up to its own
        // ~30s wait and must NOT be mistaken for ambiguity).
        private const val AMBIGUITY_GRACE_MS = 700L
    }

    override suspend fun isAvailable(): Boolean = usb.isAvailable() || nfc.isAvailable()

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    override suspend fun connect(): Unit = coroutineScope {
        stickyMode?.let { mode ->
            val transport = if (mode == Fido2TransportMode.USB) usb else nfc
            try {
                transport.connect()
                active = transport
                return@coroutineScope
            } catch (e: Exception) {
                // The sticky transport is genuinely gone (e.g. the user
                // switched physical device) - fall through to a fresh race
                // rather than getting stuck retrying a transport that will
                // never come back.
                stickyMode = null
            }
        }

        val usbDeferred = async { runCatching { usb.connect() }.isSuccess }
        val nfcDeferred = async { runCatching { nfc.connect() }.isSuccess }

        // Wait until at least one succeeds, or both fail.
        var firstSuccess: Fido2TransportMode? = null
        while (firstSuccess == null) {
            if (usbDeferred.isCompleted && nfcDeferred.isCompleted) {
                if (usbDeferred.getCompleted()) {
                    firstSuccess = Fido2TransportMode.USB
                } else if (nfcDeferred.getCompleted()) {
                    firstSuccess = Fido2TransportMode.NFC
                } else {
                    throw Ctap2TransportException.NotAvailable()
                }
                break
            }
            select<Unit> {
                if (!usbDeferred.isCompleted) usbDeferred.onAwait { }
                if (!nfcDeferred.isCompleted) nfcDeferred.onAwait { }
            }
            if (usbDeferred.isCompleted && usbDeferred.getCompleted()) firstSuccess = Fido2TransportMode.USB
            else if (nfcDeferred.isCompleted && nfcDeferred.getCompleted()) firstSuccess = Fido2TransportMode.NFC
        }

        // Give the other transport a short grace window to also succeed,
        // to detect genuine ambiguity rather than deciding instantly.
        val other = if (firstSuccess == Fido2TransportMode.USB) nfcDeferred else usbDeferred
        if (!other.isCompleted) {
            withTimeoutOrNull(AMBIGUITY_GRACE_MS) { other.await() }
        }
        val bothSucceeded = usbDeferred.isCompleted && usbDeferred.getCompleted() &&
            nfcDeferred.isCompleted && nfcDeferred.getCompleted()

        val chosen = if (bothSucceeded) {
            requestChoice() ?: run {
                // User cancelled the choice - disconnect both, surface as unavailable.
                runCatching { usb.disconnect() }
                runCatching { nfc.disconnect() }
                throw Ctap2TransportException.ConnectionFailed("No transport chosen")
            }
        } else {
            firstSuccess
        }

        // Cancelling the loser's own async job (not just calling disconnect()
        // on it) matters a great deal: this whole function is a
        // coroutineScope { } block, which won't return until EVERY child
        // coroutine finishes - disconnect() alone doesn't touch the losing
        // side's in-flight connect() coroutine (e.g. UsbCtap2Transport still
        // suspended inside its own 30s waitForAttachAndOpen wait), so without
        // explicitly cancelling it, a real successful NFC/USB connection
        // still silently blocked here for the loser's FULL remaining
        // timeout - confirmed via live hardware testing: NFC connected and
        // selected the FIDO2 applet almost immediately, but this function
        // didn't return for another ~25s (USB's leftover wait), by which
        // point the caller's own overall operation timeout had already
        // fired and reported "Signing failed".
        if (chosen != Fido2TransportMode.USB) {
            usbDeferred.cancel()
            runCatching { usb.disconnect() }
        }
        if (chosen != Fido2TransportMode.NFC) {
            nfcDeferred.cancel()
            runCatching { nfc.disconnect() }
        }
        active = if (chosen == Fido2TransportMode.USB) usb else nfc
        stickyMode = chosen
    }

    // Deliberately does NOT clear stickyMode - Ctap2TransportBridge calls
    // disconnect() as part of its own catch-disconnect-reconnect-retry-once
    // cycle on a transient send() error, and the following connect() must
    // still prefer the transport that was already working (see stickyMode's
    // doc comment). stickyMode only resets when that reconnect itself fails.
    override suspend fun disconnect() {
        active?.disconnect()
        active = null
    }

    override suspend fun send(command: ByteArray): ByteArray =
        active?.send(command) ?: throw Ctap2TransportException.DeviceDisconnected()
}
