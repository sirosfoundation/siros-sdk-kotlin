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
import android.util.Base64
import android.util.Log
import com.upokecenter.cbor.CBORObject
import uniffi.siros_wscd_manager.FfiCtap2Transport
import uniffi.siros_wscd_manager.FfiWscdException
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * USB HID CTAP2 transport for FIDO2 authenticators (e.g. YubiKey).
 *
 * Implements the [FfiCtap2Transport] callback interface so the Rust
 * previewSign plugin can perform makeCredential and getAssertion
 * operations on a hardware authenticator connected via USB.
 *
 * Protocol layers:
 * 1. USB HID — 64-byte packets to/from the authenticator
 * 2. CTAPHID — channel allocation + command framing (FIDO v2.1 §11.2)
 * 3. CTAP2 CBOR — authenticatorMakeCredential / authenticatorGetAssertion
 */
class UsbCtap2Transport(private val context: Context) : FfiCtap2Transport {

    companion object {
        private const val TAG = "UsbCtap2Transport"

        // Yubico vendor ID
        private const val YUBICO_VENDOR_ID = 0x1050

        // CTAPHID commands (bit 7 set = initialization packet)
        private const val CTAPHID_INIT: Byte = (0x06 or 0x80).toByte()
        private const val CTAPHID_CBOR: Byte = (0x10 or 0x80).toByte()
        private const val CTAPHID_ERROR: Byte = (0x3F or 0x80).toByte()
        private const val CTAPHID_KEEPALIVE: Byte = (0x3B or 0x80).toByte()

        // CTAP2 commands
        private const val CTAP2_MAKE_CREDENTIAL: Byte = 0x01
        private const val CTAP2_GET_ASSERTION: Byte = 0x02

        // Broadcast channel for CTAPHID_INIT
        private val CID_BROADCAST = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())

        // COSE key map labels
        private const val COSE_KEY_ALG = 3
        private const val COSE_KEY_X = -2
        private const val COSE_KEY_Y = -3

        // HID packet size
        private const val HID_PACKET_SIZE = 64
        private const val INIT_DATA_SIZE = 57  // 64 - 4(CID) - 1(CMD) - 2(LEN)
        private const val CONT_DATA_SIZE = 59  // 64 - 4(CID) - 1(SEQ)

        // Timeout for USB operations (ms)
        private const val USB_TIMEOUT_MS = 30_000

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
        } ?: throw FfiWscdException.NoPlugin("No FIDO2 USB device found")

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
                throw FfiWscdException.Plugin("USB permission request timed out")
            }
            if (!granted) {
                throw FfiWscdException.Plugin("USB permission denied by user")
            }
            Log.i(TAG, "USB permission granted")
        }

        // Find the FIDO HID interface (usage page 0xF1D0)
        val (iface, inEp, outEp) = findFidoEndpoints(device)

        val connection = usbManager.openDevice(device)
            ?: throw FfiWscdException.Plugin("Failed to open USB device")

        if (!connection.claimInterface(iface, true)) {
            connection.close()
            throw FfiWscdException.Plugin("Failed to claim FIDO HID interface")
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
            ?: throw FfiWscdException.Plugin("No FIDO HID endpoints found on device")

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

        throw FfiWscdException.Plugin("Failed to allocate CTAPHID channel after $retries retries")
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
            if (drained > 50) break  // safety limit
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
                    throw FfiWscdException.Plugin("Too many packets with wrong CID")
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
                    throw FfiWscdException.Plugin("Timed out waiting for authenticator (>600 keepalives)")
                }
                continue
            }

            // Got a non-keepalive response
            break
        }

        val cmd = initPacket[4]
        if (cmd == CTAPHID_ERROR) {
            val errorCode = initPacket[7].toInt() and 0xFF
            throw FfiWscdException.Plugin("CTAPHID error: 0x${errorCode.toString(16)}")
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
            throw FfiWscdException.Plugin("USB bulk transfer send failed (rc=$sent)")
        }
    }

    private fun recvPacket(session: UsbSession): ByteArray {
        val buffer = ByteArray(HID_PACKET_SIZE)
        val received = session.connection.bulkTransfer(session.inEp, buffer, buffer.size, USB_TIMEOUT_MS)
        if (received < 0) {
            throw FfiWscdException.Plugin("USB bulk transfer receive failed (rc=$received)")
        }
        return buffer
    }

    // ── CTAP2 CBOR commands ──────────────────────────────────────────────────

    override fun ctap2MakeCredential(
        clientDataHash: ByteArray,
        rpId: String,
        userId: ByteArray,
        algorithms: List<Long>,
    ): ByteArray {
        Log.i(TAG, "makeCredential: rpId=$rpId, algorithms=$algorithms")

        val session = openFidoDevice()
        try {
            val cid = ctaphidInit(session)

            // Build CBOR for authenticatorMakeCredential (0x01)
            // Use NewOrderedMap to preserve insertion order (CTAP canonical)
            val params = CBORObject.NewOrderedMap()
            params[CBORObject.FromObject(1)] = CBORObject.FromObject(clientDataHash)  // clientDataHash
            
            val rpMap = CBORObject.NewOrderedMap()
            rpMap[CBORObject.FromObject("id")] = CBORObject.FromObject(rpId)
            rpMap[CBORObject.FromObject("name")] = CBORObject.FromObject(rpId)
            params[CBORObject.FromObject(2)] = rpMap
            
            val userMap = CBORObject.NewOrderedMap()
            userMap[CBORObject.FromObject("id")] = CBORObject.FromObject(userId)
            userMap[CBORObject.FromObject("name")] = CBORObject.FromObject("wscd-user")
            userMap[CBORObject.FromObject("displayName")] = CBORObject.FromObject("WSCD User")
            params[CBORObject.FromObject(3)] = userMap
            
            val algEntry = CBORObject.NewOrderedMap()
            algEntry[CBORObject.FromObject("alg")] = CBORObject.FromObject(-7)
            algEntry[CBORObject.FromObject("type")] = CBORObject.FromObject("public-key")
            val pubKeyCredParams = CBORObject.NewArray()
            pubKeyCredParams.Add(algEntry)
            params[CBORObject.FromObject(4)] = pubKeyCredParams

            // No options — skip rk and uv for maximum compatibility
            // YubiKey will default to non-resident, no UV

            val cbor = params.EncodeToBytes()
            val payload = ByteArray(1 + cbor.size)
            payload[0] = CTAP2_MAKE_CREDENTIAL
            cbor.copyInto(payload, 1)

            val response = ctaphidCbor(session, cid, payload)

            // First byte is CTAP2 status
            val status = response[0].toInt() and 0xFF
            if (status != 0x00) {
                throw FfiWscdException.Plugin("CTAP2 makeCredential error: 0x${status.toString(16)}")
            }

            // Parse attestation object from response[1..]
            val attObj = CBORObject.DecodeFromBytes(response.copyOfRange(1, response.size))
            return parseAttestationObject(attObj)
        } finally {
            session.close()
        }
    }

    override fun ctap2GetAssertion(
        rpId: String,
        challenge: ByteArray,
        credentialHandles: List<ByteArray>,
        dataToSign: List<ByteArray>,
    ): List<ByteArray> {
        Log.i(TAG, "getAssertion: rpId=$rpId, credentials=${credentialHandles.size}")

        val session = openFidoDevice()
        try {
            val cid = ctaphidInit(session)

            // Build CBOR for authenticatorGetAssertion (0x02)
            val params = CBORObject.NewMap()
            params.Set(CBORObject.FromObject(1), CBORObject.FromObject(rpId))       // rpId
            params.Set(CBORObject.FromObject(2), CBORObject.FromObject(challenge)) // clientDataHash

            // allowList
            params.Set(CBORObject.FromObject(3), CBORObject.NewArray().apply {
                for (handle in credentialHandles) {
                    Add(CBORObject.NewMap().apply {
                        Set("type", CBORObject.FromObject("public-key"))
                        Set("id", CBORObject.FromObject(handle))
                    })
                }
            })

            // Options - no UV for compatibility
            // (YubiKey requires PIN setup for UV)

            // rawSign extension: pass data-to-sign in extensions (key 6)
            if (dataToSign.isNotEmpty()) {
                params.Set(CBORObject.FromObject(6), CBORObject.NewMap().apply {
                    Set("rawSign", CBORObject.NewMap().apply {
                        Set("dataToSign", CBORObject.NewArray().apply {
                            for (data in dataToSign) {
                                Add(CBORObject.FromObject(data))
                            }
                        })
                    })
                })
            }

            val cbor = params.EncodeToBytes()
            val payload = ByteArray(1 + cbor.size)
            payload[0] = CTAP2_GET_ASSERTION
            cbor.copyInto(payload, 1)

            val response = ctaphidCbor(session, cid, payload)

            val status = response[0].toInt() and 0xFF
            if (status != 0x00) {
                throw FfiWscdException.Plugin("CTAP2 getAssertion error: 0x${status.toString(16)}")
            }

            // Parse assertion response
            val assertObj = CBORObject.DecodeFromBytes(response.copyOfRange(1, response.size))
            return parseAssertionSignatures(assertObj, dataToSign.size)
        } finally {
            session.close()
        }
    }

    // ── Response parsing ─────────────────────────────────────────────────────

    /**
     * Parse CBOR attestation object into the JSON format expected by PreviewSignPlugin:
     * { "key_handle": "<base64url>", "public_key": {"x": "<b64u>", "y": "<b64u>"}, "algorithm": -7, "attestation_object": "<b64u>" }
     */
    private fun parseAttestationObject(attObj: CBORObject): ByteArray {
        // CTAP2 makeCredential response uses integer keys:
        // 1 = fmt (text), 2 = authData (bytes), 3 = attStmt (map)
        val authDataObj: CBORObject = attObj.get(CBORObject.FromObject(2))
            ?: attObj.get("authData")  // fallback to string key
            ?: throw FfiWscdException.Plugin("Missing authData in attestation object")
        val authData: ByteArray = authDataObj.GetByteString()

        // authData layout:
        // rpIdHash(32) || flags(1) || signCount(4) || attestedCredentialData { aaguid(16) || credIdLen(2) || credId(N) || credPubKey(COSE) }
        if (authData.size < 37) {
            throw FfiWscdException.Plugin("authData too short: ${authData.size}")
        }

        val flags = authData[32].toInt() and 0xFF
        val hasAttestedData = (flags and 0x40) != 0

        if (!hasAttestedData) {
            throw FfiWscdException.Plugin("authData does not contain attested credential data")
        }

        // Parse attested credential data starting at offset 37
        var offset = 37
        // aaguid (16 bytes) - skip
        offset += 16

        // credIdLen (2 bytes big-endian)
        val credIdLen = ((authData[offset].toInt() and 0xFF) shl 8) or (authData[offset + 1].toInt() and 0xFF)
        offset += 2

        // credId (credential handle)
        val credId = authData.copyOfRange(offset, offset + credIdLen)
        offset += credIdLen

        // credPubKey (COSE key - CBOR encoded)
        val coseKey = CBORObject.DecodeFromBytes(authData.copyOfRange(offset, authData.size))

        val xObj: CBORObject = coseKey.get(CBORObject.FromObject(COSE_KEY_X))
            ?: throw FfiWscdException.Plugin("Missing x coordinate in COSE key")
        val x: ByteArray = xObj.GetByteString()
        val yObj: CBORObject = coseKey.get(CBORObject.FromObject(COSE_KEY_Y))
            ?: throw FfiWscdException.Plugin("Missing y coordinate in COSE key")
        val y: ByteArray = yObj.GetByteString()
        val algObj: CBORObject? = coseKey.get(CBORObject.FromObject(COSE_KEY_ALG))
        val algorithm: Long = algObj?.AsInt64() ?: -7L

        // Re-encode the entire attestation object
        val attObjBytes = attObj.EncodeToBytes()

        // Build the JSON response expected by PreviewSignPlugin
        val json = org.json.JSONObject().apply {
            put("key_handle", base64UrlEncode(credId))
            put("public_key", org.json.JSONObject().apply {
                put("x", base64UrlEncode(x))
                put("y", base64UrlEncode(y))
            })
            put("algorithm", algorithm)
            put("attestation_object", base64UrlEncode(attObjBytes))
        }

        Log.i(TAG, "makeCredential success: credId=${credId.size} bytes, alg=$algorithm")
        return json.toString().toByteArray()
    }

    /**
     * Parse assertion response to extract signatures.
     *
     * Standard assertion response: { 1: credential, 2: authData, 3: signature }
     * With rawSign extension, signatures may be in extensions (key 4).
     */
    private fun parseAssertionSignatures(assertObj: CBORObject, expectedCount: Int): List<ByteArray> {
        // Try rawSign extension response first
        val extensions: CBORObject? = assertObj.get(CBORObject.FromObject(4))
        if (extensions != null) {
            val rawSign: CBORObject? = extensions.get("rawSign")
            if (rawSign != null) {
                val sigs: CBORObject? = rawSign.get("signatures")
                if (sigs != null && sigs.type == com.upokecenter.cbor.CBORType.Array) {
                    return (0 until sigs.size()).map { i ->
                        sigs.get(i).GetByteString()
                    }
                }
            }
        }

        // Fall back to standard signature field
        val signature: ByteArray = assertObj.get(CBORObject.FromObject(3))?.GetByteString()
            ?: throw FfiWscdException.Plugin("No signature in assertion response")

        return listOf(signature)
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private fun base64UrlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }
}
