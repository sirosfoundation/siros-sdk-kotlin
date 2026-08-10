package org.siros.sdk.sample

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import org.siros.sdk.keystore.Ctap2TransportException
import org.siros.sdk.keystore.Ctap2TransportProvider
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * USB HID CTAP2 transport for FIDO2 authenticators (e.g. YubiKey).
 *
 * Implements the SDK-level [Ctap2TransportProvider] - all previewSign
 * CBOR request-building and response-parsing lives in Rust
 * (`siros-wscd-manager`'s `preview_sign_protocol` module), confirmed
 * against real YubiKey 5.8 hardware. This class only owns the physical
 * transport layers below that:
 * 1. USB HID — 64-byte packets to/from the authenticator
 * 2. CTAPHID — channel allocation + command framing (FIDO v2.1 §11.2)
 *
 * It has no CTAP2/CBOR knowledge of its own - it just moves a command's
 * bytes to the authenticator and returns whatever bytes come back.
 *
 * [connect] opens the USB device and allocates a CTAPHID channel once;
 * [send] reuses that channel for every command; [disconnect] releases it.
 */
class UsbCtap2Transport(private val context: Context) : Ctap2TransportProvider {

    private var session: UsbSession? = null
    private var cid: ByteArray? = null

    companion object {
        private const val TAG = "UsbCtap2Transport"

        // Yubico vendor ID
        private const val YUBICO_VENDOR_ID = 0x1050

        // CTAPHID commands (bit 7 set = initialization packet)
        private const val CTAPHID_INIT: Byte = (0x06 or 0x80).toByte()
        private const val CTAPHID_CBOR: Byte = (0x10 or 0x80).toByte()
        private const val CTAPHID_ERROR: Byte = (0x3F or 0x80).toByte()
        private const val CTAPHID_KEEPALIVE: Byte = (0x3B or 0x80).toByte()

        // Broadcast channel for CTAPHID_INIT
        private val CID_BROADCAST = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())

        // HID packet size
        private const val HID_PACKET_SIZE = 64
        private const val INIT_DATA_SIZE = 57 // 64 - 4(CID) - 1(CMD) - 2(LEN)
        private const val CONT_DATA_SIZE = 59 // 64 - 4(CID) - 1(SEQ)

        // Timeout for USB operations (ms)
        private const val USB_TIMEOUT_MS = 30_000

        // How long connect() waits for a matching device to be plugged in
        // when none is already attached (see waitForAttachAndOpen).
        private const val USB_ATTACH_WAIT_TIMEOUT_MS = 30_000L

        private const val ACTION_USB_PERMISSION = "org.siros.sdk.sample.USB_PERMISSION"
    }

    /**
     * Find and open a FIDO2-capable USB device.
     * Returns (connection, hidInterface, inEndpoint, outEndpoint).
     */
    private fun openFidoDevice(): UsbSession {
        val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        val device = usbManager.deviceList.values.firstOrNull { d ->
            d.vendorId == YUBICO_VENDOR_ID && hasFidoInterface(d)
        } ?: throw Ctap2TransportException.NotAvailable()

        Log.i(TAG, "Found FIDO2 device: ${device.productName} (${device.vendorId}:${device.productId})")

        if (!usbManager.hasPermission(device)) {
            Log.i(TAG, "Requesting USB permission for ${device.productName}")
            val latch = CountDownLatch(1)
            var granted = false

            val receiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context, intent: Intent) {
                    if (ACTION_USB_PERMISSION == intent.action) {
                        granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                        latch.countDown()
                    }
                }
            }
            context.registerReceiver(
                receiver,
                IntentFilter(ACTION_USB_PERMISSION),
                Context.RECEIVER_NOT_EXPORTED,
            )

            val pi = PendingIntent.getBroadcast(
                context, 0,
                Intent(ACTION_USB_PERMISSION).apply { setPackage(context.packageName) },
                PendingIntent.FLAG_MUTABLE,
            )
            usbManager.requestPermission(device, pi)

            // Block until user responds (up to 30s)
            val answered = latch.await(30, TimeUnit.SECONDS)
            context.unregisterReceiver(receiver)

            if (!answered) {
                throw Ctap2TransportException.ConnectionFailed("USB permission request timed out")
            }
            if (!granted) {
                throw Ctap2TransportException.ConnectionFailed("USB permission denied by user")
            }
            Log.i(TAG, "USB permission granted")
        }

        // Find the FIDO HID interface (usage page 0xF1D0)
        val (iface, inEp, outEp) = findFidoEndpoints(device)

        val connection = usbManager.openDevice(device)
            ?: throw Ctap2TransportException.ConnectionFailed("Failed to open USB device")

        if (!connection.claimInterface(iface, true)) {
            connection.close()
            throw Ctap2TransportException.ConnectionFailed("Failed to claim FIDO HID interface")
        }

        return UsbSession(connection, iface, inEp, outEp)
    }

    private fun hasFidoInterface(device: UsbDevice): Boolean {
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            // FIDO HID class=3 (HID), subclass=0, protocol=0
            if (iface.interfaceClass == UsbConstants.USB_CLASS_HID) {
                return true
            }
        }
        return false
    }

    private data class EndpointInfo(val iface: UsbInterface, val inEp: UsbEndpoint, val outEp: UsbEndpoint)

    private fun findFidoEndpoints(device: UsbDevice): EndpointInfo {
        // Try FIDO interface first (subclass=0, protocol=0), fall back to any HID
        val candidates = mutableListOf<Triple<UsbInterface, UsbEndpoint, UsbEndpoint>>()

        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            if (iface.interfaceClass != UsbConstants.USB_CLASS_HID) continue

            var inEp: UsbEndpoint? = null
            var outEp: UsbEndpoint? = null

            for (j in 0 until iface.endpointCount) {
                val ep = iface.getEndpoint(j)
                if (ep.type == UsbConstants.USB_ENDPOINT_XFER_INT) {
                    if (ep.direction == UsbConstants.USB_DIR_IN) inEp = ep
                    else outEp = ep
                }
            }

            if (inEp != null && outEp != null) {
                    candidates.add(Triple(iface, inEp, outEp))
            }
        }

        // Prefer FIDO interface (subclass=0, protocol=0) over OTP (subclass=1, protocol=1)
        val (iface, inEp, outEp) = candidates.firstOrNull { (iface, _, _) ->
            iface.interfaceSubclass == 0 && iface.interfaceProtocol == 0
        } ?: candidates.firstOrNull()
            ?: throw Ctap2TransportException.ConnectionFailed("No FIDO HID endpoints found on device")

        return EndpointInfo(iface, inEp, outEp)
    }

    private data class UsbSession(
        val connection: UsbDeviceConnection,
        val iface: UsbInterface,
        val inEp: UsbEndpoint,
        val outEp: UsbEndpoint,
    ) : AutoCloseable {
        override fun close() {
            connection.releaseInterface(iface)
            connection.close()
        }
    }

    // ── CTAPHID framing ──────────────────────────────────────────────────────

    /**
     * Allocate a CTAPHID channel via CTAPHID_INIT.
     */
    private fun ctaphidInit(session: UsbSession): ByteArray {
        // Drain any stale data from previous sessions
        drainStalePackets(session)

        val nonce = Random.nextBytes(8)

        // Build CTAPHID_INIT packet
        val packet = ByteArray(HID_PACKET_SIZE)
        CID_BROADCAST.copyInto(packet, 0)
        packet[4] = CTAPHID_INIT
        packet[5] = 0 // length high
        packet[6] = 8 // length low (8 bytes nonce)
        nonce.copyInto(packet, 7)

        sendPacket(session, packet)

        // Read responses until we get the INIT response matching our nonce
        var retries = 0
        while (retries < 20) {
            val response = recvPacket(session)
            retries++

            // Check if this is a CTAPHID_INIT response (cmd byte at offset 4)
            val cmd = response[4]
            if (cmd != CTAPHID_INIT) {
                Log.w(TAG, "Skipping non-INIT response: cmd=0x${(cmd.toInt() and 0xFF).toString(16)}")
                continue
            }

            // Verify nonce match (bytes 7..14 in response should match our nonce)
            var nonceMatch = true
            for (i in 0..7) {
                if (response[7 + i] != nonce[i]) {
                    nonceMatch = false
                    break
                }
            }
            if (!nonceMatch) {
                Log.w(TAG, "Skipping INIT response with wrong nonce")
                continue
            }

            // Response: nonce(8) || CID(4) || protocol(1) || major(1) || minor(1) || build(1) || capabilities(1)
            val cid = ByteArray(4)
            System.arraycopy(response, 15, cid, 0, 4) // offset 7+8=15 for new CID
            Log.i(TAG, "CTAPHID channel allocated: ${cid.toHex()}")
            return cid
        }

        throw Ctap2TransportException.ConnectionFailed("Failed to allocate CTAPHID channel after $retries retries")
    }

    /**
     * Drain any stale packets from previous sessions.
     */
    private fun drainStalePackets(session: UsbSession) {
        val buffer = ByteArray(HID_PACKET_SIZE)
        var drained = 0
        // Use short timeout (50ms) to quickly detect if there's stale data
        while (true) {
            val received = session.connection.bulkTransfer(session.inEp, buffer, buffer.size, 50)
            if (received <= 0) break
            drained++
            if (drained > 50) break // safety limit
        }
        if (drained > 0) {
            Log.i(TAG, "Drained $drained stale packets from USB pipe")
        }
    }

    /**
     * Send a CTAP2 CBOR command and receive the response.
     */
    private fun ctaphidCbor(session: UsbSession, cid: ByteArray, data: ByteArray): ByteArray {
        // Frame into CTAPHID packets
        val packets = frameCtaphid(cid, CTAPHID_CBOR, data)
        for (pkt in packets) {
            sendPacket(session, pkt)
        }

        // Receive response
        return recvCtaphidResponse(session, cid)
    }

    private fun frameCtaphid(cid: ByteArray, cmd: Byte, data: ByteArray): List<ByteArray> {
        val packets = mutableListOf<ByteArray>()

        // Initialization packet
        val initPacket = ByteArray(HID_PACKET_SIZE)
        cid.copyInto(initPacket, 0)
        initPacket[4] = cmd
        initPacket[5] = ((data.size shr 8) and 0xFF).toByte()
        initPacket[6] = (data.size and 0xFF).toByte()

        val initCopy = minOf(data.size, INIT_DATA_SIZE)
        data.copyInto(initPacket, 7, 0, initCopy)
        packets.add(initPacket)

        // Continuation packets
        var offset = initCopy
        var seq = 0
        while (offset < data.size) {
            val contPacket = ByteArray(HID_PACKET_SIZE)
            cid.copyInto(contPacket, 0)
            contPacket[4] = (seq and 0x7F).toByte()

            val contCopy = minOf(data.size - offset, CONT_DATA_SIZE)
            data.copyInto(contPacket, 5, offset, offset + contCopy)
            packets.add(contPacket)

            offset += contCopy
            seq++
        }

        return packets
    }

    private fun recvCtaphidResponse(session: UsbSession, expectedCid: ByteArray): ByteArray {
        // Read packets, handling KEEPALIVE and skipping wrong CIDs
        var initPacket: ByteArray
        var retries = 0
        var keepaliveCount = 0
        while (true) {
            initPacket = recvPacket(session)

            // Check CID match
            val cidMatch = (0..3).all { initPacket[it] == expectedCid[it] }
            if (!cidMatch) {
                retries++
                Log.w(TAG, "Skipping packet with wrong CID: ${initPacket.copyOfRange(0, 4).toHex()} (expected ${expectedCid.toHex()})")
                if (retries > 10) {
                    throw Ctap2TransportException.InvalidResponse("Too many packets with wrong CID")
                }
                continue
            }

            val cmd = initPacket[4]

            // Handle KEEPALIVE packets — authenticator is still processing
            if (cmd == CTAPHID_KEEPALIVE) {
                val status = initPacket[7].toInt() and 0xFF
                keepaliveCount++
                if (status == 2 && keepaliveCount == 1) {
                    Log.i(TAG, "Waiting for user presence — touch the YubiKey")
                }
                // Keep reading — the authenticator will eventually send the real response
                if (keepaliveCount > 600) { // ~30s at 20 keepalives/sec
                    throw Ctap2TransportException.Timeout()
                }
                continue
            }

            // Got a non-keepalive response
            break
        }

        val cmd = initPacket[4]
        if (cmd == CTAPHID_ERROR) {
            val errorCode = initPacket[7].toInt() and 0xFF
            throw Ctap2TransportException.InvalidResponse("CTAPHID error: 0x${errorCode.toString(16)}")
        }

        val totalLen = ((initPacket[5].toInt() and 0xFF) shl 8) or (initPacket[6].toInt() and 0xFF)
        val output = ByteArrayOutputStream(totalLen)

        val initData = minOf(totalLen, INIT_DATA_SIZE)
        output.write(initPacket, 7, initData)

        // Read continuation packets
        var remaining = totalLen - initData
        while (remaining > 0) {
            val contPacket = recvPacket(session)
            val contData = minOf(remaining, CONT_DATA_SIZE)
            output.write(contPacket, 5, contData)
            remaining -= contData
        }

        return output.toByteArray()
    }

    private fun sendPacket(session: UsbSession, packet: ByteArray) {
        val sent = session.connection.bulkTransfer(session.outEp, packet, packet.size, USB_TIMEOUT_MS)
        if (sent < 0) {
            throw Ctap2TransportException.DeviceDisconnected()
        }
    }

    private fun recvPacket(session: UsbSession): ByteArray {
        val buffer = ByteArray(HID_PACKET_SIZE)
        val received = session.connection.bulkTransfer(session.inEp, buffer, buffer.size, USB_TIMEOUT_MS)
        if (received < 0) {
            throw Ctap2TransportException.DeviceDisconnected()
        }
        return buffer
    }

    // ── Ctap2TransportProvider ────────────────────────────────────────────────

    override suspend fun isAvailable(): Boolean {
        val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        return usbManager.deviceList.values.any { it.vendorId == YUBICO_VENDOR_ID && hasFidoInterface(it) }
    }

    /**
     * Opens an already-attached FIDO device if one exists, otherwise waits
     * for [UsbManager.ACTION_USB_DEVICE_ATTACHED] up to
     * [USB_ATTACH_WAIT_TIMEOUT_MS] - lets this transport be raced against
     * [NfcCtap2Transport] (see `CompositeCtap2Transport`) without requiring
     * the key to already be plugged in before the race starts.
     */
    override suspend fun connect() {
        val newSession = try {
            openFidoDevice()
        } catch (e: Ctap2TransportException.NotAvailable) {
            waitForAttachAndOpen()
        }
        try {
            cid = ctaphidInit(newSession)
        } catch (e: Exception) {
            newSession.close()
            throw e
        }
        session = newSession
    }

    private suspend fun waitForAttachAndOpen(): UsbSession {
        val deviceDeferred = CompletableDeferred<UsbDevice>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action != UsbManager.ACTION_USB_DEVICE_ATTACHED) return
                val device = intent.getParcelableExtraCompat<UsbDevice>(UsbManager.EXTRA_DEVICE) ?: return
                if (device.vendorId == YUBICO_VENDOR_ID && hasFidoInterface(device)) {
                    deviceDeferred.complete(device)
                }
            }
        }
        context.registerReceiver(receiver, IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED), Context.RECEIVER_NOT_EXPORTED)
        try {
            Log.i(TAG, "Waiting for USB attach - plug in the security key")
            withTimeout(USB_ATTACH_WAIT_TIMEOUT_MS) { deviceDeferred.await() }
        } catch (e: TimeoutCancellationException) {
            throw Ctap2TransportException.NotAvailable()
        } finally {
            context.unregisterReceiver(receiver)
        }
        return openFidoDevice()
    }

    override suspend fun disconnect() {
        session?.close()
        session = null
        cid = null
    }

    /**
     * Send a raw CTAP2 command (already CBOR-encoded with its leading
     * command byte, built by Rust's `preview_sign_protocol` module) and
     * return the raw response bytes exactly as received (leading status
     * byte + CBOR body). No CBOR knowledge here - Rust does all
     * encoding/decoding on both sides of this call.
     */
    override suspend fun send(command: ByteArray): ByteArray {
        val activeSession = session ?: throw Ctap2TransportException.DeviceDisconnected()
        val activeCid = cid ?: throw Ctap2TransportException.DeviceDisconnected()
        Log.i(TAG, "CTAP2 command (${command.size}B): ${command.toHex()}")
        val response = ctaphidCbor(activeSession, activeCid, command)
        Log.i(TAG, "CTAP2 response (${response.size}B): ${response.toHex()}")
        return response
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    private inline fun <reified T> Intent.getParcelableExtraCompat(name: String): T? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            getParcelableExtra(name, T::class.java)
        } else {
            @Suppress("DEPRECATION")
            getParcelableExtra(name) as? T
        }
}
