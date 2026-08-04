// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

/**
 * ISO 18013-5 §8.2.1.1/§8.2.2.3 device engagement: builds the `DeviceEngagement`
 * CBOR structure and its `mdoc:` URI encoding for QR-code proximity presentation.
 *
 * Cipher suite 1 only (ECDH/ECDSA over curve P-256, per §9.1.5.2 Table 22 - the
 * only cipher suite this document's session-encryption mechanisms describe).
 *
 * Generates a fresh `EDeviceKey` ephemeral keypair per engagement - the private
 * key is returned (never encoded into the CBOR) since it's needed later for the
 * ECKA-DH session-key derivation once a reader connects (§9.1.1.4/§9.1.1.5).
 */
object DeviceEngagement {

    /** Cipher suite identifier per §9.1.5.2 - this document only defines suite 1. */
    private const val CIPHER_SUITE_1 = 1L

    // COSE_Key labels (RFC 8152 §7/13.1.1) for an EC2 (P-256) public key.
    private const val COSE_KEY_KTY = 1L
    private const val COSE_KEY_CRV = -1L
    private const val COSE_KEY_X = -2L
    private const val COSE_KEY_Y = -3L
    private const val COSE_KTY_EC2 = 2L
    private const val COSE_CRV_P256 = 1L

    // DeviceRetrievalMethod type/version per Table 7.
    private const val RETRIEVAL_TYPE_BLE = 2L
    private const val RETRIEVAL_VERSION_BLE = 1L

    // BleOptions keys per §8.2.2.3.
    private const val BLE_SUPPORTS_PERIPHERAL_SERVER_MODE = 0L
    private const val BLE_SUPPORTS_CENTRAL_CLIENT_MODE = 1L
    private const val BLE_PERIPHERAL_SERVER_MODE_UUID = 10L
    private const val BLE_CENTRAL_CLIENT_MODE_UUID = 11L

    private val base64Url = Base64.getUrlEncoder().withoutPadding()

    /** The result of generating a device engagement: bytes/URI to hand to a reader, plus the key material needed later for session encryption. */
    data class Engagement(
        /** Raw `DeviceEngagement` CBOR bytes - needed verbatim (as `DeviceEngagementBytes`) when building the proximity `SessionTranscript`. */
        val deviceEngagementBytes: ByteArray,
        /** `"mdoc:" + base64url-without-padding(deviceEngagementBytes)`, per §8.2.2.3 - the QR code payload. */
        val mdocUri: String,
        /** The ephemeral `EDeviceKey` key pair generated for this engagement. */
        val publicKey: ECPublicKey,
        val privateKey: ECPrivateKey,
        /**
         * `EDeviceKeyBytes` (`#6.24(bstr .cbor EDeviceKey)`) exactly as
         * embedded in [deviceEngagementBytes] - needed as the `Ident`
         * characteristic's IKM (§11.1.3.1) when verifying a reader's
         * identity in mdoc central client mode; kept as its own field
         * rather than re-parsed from [deviceEngagementBytes] each time.
         */
        val eDeviceKeyBytes: ByteArray,
        /** Fresh UUID advertised for BLE peripheral-server-mode discovery, if that mode is offered. */
        val peripheralServerModeUuid: UUID?,
        /** Fresh UUID advertised for BLE central-client-mode discovery, if that mode is offered. */
        val centralClientModeUuid: UUID?,
    )

    /**
     * Build a fresh device engagement offering BLE data retrieval.
     *
     * @param supportsCentralClientMode advertise mdoc-as-GATT-client mode (§8.3.3.1.1).
     * @param supportsPeripheralServerMode advertise mdoc-as-GATT-server mode (§8.3.3.1.1).
     */
    fun create(
        supportsCentralClientMode: Boolean = true,
        supportsPeripheralServerMode: Boolean = true,
    ): Engagement {
        require(supportsCentralClientMode || supportsPeripheralServerMode) {
            "device engagement must offer at least one BLE mode"
        }

        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val publicKey = keyPair.public as ECPublicKey
        val privateKey = keyPair.private as ECPrivateKey

        val peripheralUuid = if (supportsPeripheralServerMode) UUID.randomUUID() else null
        val centralUuid = if (supportsCentralClientMode) UUID.randomUUID() else null

        val deviceEngagementBytes = encode(
            publicKey = publicKey,
            supportsCentralClientMode = supportsCentralClientMode,
            supportsPeripheralServerMode = supportsPeripheralServerMode,
            peripheralUuid = peripheralUuid,
            centralUuid = centralUuid,
        )
        val mdocUri = "mdoc:" + base64Url.encodeToString(deviceEngagementBytes)

        return Engagement(
            deviceEngagementBytes = deviceEngagementBytes,
            mdocUri = mdocUri,
            publicKey = publicKey,
            privateKey = privateKey,
            eDeviceKeyBytes = eDeviceKeyBytes(publicKey),
            peripheralServerModeUuid = peripheralUuid,
            centralClientModeUuid = centralUuid,
        )
    }

    /** `EDeviceKeyBytes = #6.24(bstr .cbor EDeviceKey)`, per §9.1/§12.2.4. */
    private fun eDeviceKeyBytes(publicKey: ECPublicKey): ByteArray =
        CBORObject.FromObjectAndTag(coseKey(publicKey).EncodeToBytes(), 24).EncodeToBytes()

    /**
     * Encode the `DeviceEngagement` CBOR structure per §8.2.1.1:
     * ```
     * DeviceEngagement = { 0: "1.0", 1: Security, 2: DeviceRetrievalMethods }
     * Security = [ 1, EDeviceKeyBytes ]
     * DeviceRetrievalMethods = [ [ 2, 1, BleOptions ] ]
     * ```
     */
    internal fun encode(
        publicKey: ECPublicKey,
        supportsCentralClientMode: Boolean,
        supportsPeripheralServerMode: Boolean,
        peripheralUuid: UUID?,
        centralUuid: UUID?,
    ): ByteArray {
        val eDeviceKeyBytes = CBORObject.FromObjectAndTag(coseKey(publicKey).EncodeToBytes(), 24)

        val security = CBORObject.NewArray()
        security.Add(CBORObject.FromObject(CIPHER_SUITE_1))
        security.Add(eDeviceKeyBytes)

        val bleOptions = CBORObject.NewMap()
        bleOptions[CBORObject.FromObject(BLE_SUPPORTS_PERIPHERAL_SERVER_MODE)] =
            CBORObject.FromObject(supportsPeripheralServerMode)
        bleOptions[CBORObject.FromObject(BLE_SUPPORTS_CENTRAL_CLIENT_MODE)] =
            CBORObject.FromObject(supportsCentralClientMode)
        peripheralUuid?.let {
            bleOptions[CBORObject.FromObject(BLE_PERIPHERAL_SERVER_MODE_UUID)] =
                CBORObject.FromObject(uuidBytes(it))
        }
        centralUuid?.let {
            bleOptions[CBORObject.FromObject(BLE_CENTRAL_CLIENT_MODE_UUID)] =
                CBORObject.FromObject(uuidBytes(it))
        }

        val bleRetrievalMethod = CBORObject.NewArray()
        bleRetrievalMethod.Add(CBORObject.FromObject(RETRIEVAL_TYPE_BLE))
        bleRetrievalMethod.Add(CBORObject.FromObject(RETRIEVAL_VERSION_BLE))
        bleRetrievalMethod.Add(bleOptions)

        val deviceRetrievalMethods = CBORObject.NewArray()
        deviceRetrievalMethods.Add(bleRetrievalMethod)

        val deviceEngagement = CBORObject.NewMap()
        deviceEngagement[CBORObject.FromObject(0L)] = CBORObject.FromObject("1.0")
        deviceEngagement[CBORObject.FromObject(1L)] = security
        deviceEngagement[CBORObject.FromObject(2L)] = deviceRetrievalMethods

        return deviceEngagement.EncodeToBytes()
    }

    /** COSE_Key (RFC 8152 §13.1.1) for an uncompressed P-256 public point. */
    private fun coseKey(publicKey: ECPublicKey): CBORObject {
        val x = padOrTrim(publicKey.w.affineX.toByteArray(), 32)
        val y = padOrTrim(publicKey.w.affineY.toByteArray(), 32)
        val key = CBORObject.NewMap()
        key[CBORObject.FromObject(COSE_KEY_KTY)] = CBORObject.FromObject(COSE_KTY_EC2)
        key[CBORObject.FromObject(COSE_KEY_CRV)] = CBORObject.FromObject(COSE_CRV_P256)
        key[CBORObject.FromObject(COSE_KEY_X)] = CBORObject.FromObject(x)
        key[CBORObject.FromObject(COSE_KEY_Y)] = CBORObject.FromObject(y)
        return key
    }

    private fun padOrTrim(bytes: ByteArray, len: Int): ByteArray = when {
        bytes.size == len -> bytes
        bytes.size > len -> bytes.copyOfRange(bytes.size - len, bytes.size) // strip BigInteger's leading sign byte
        else -> ByteArray(len - bytes.size) + bytes
    }

    private fun uuidBytes(uuid: UUID): ByteArray {
        val bytes = ByteArray(16)
        val msb = uuid.mostSignificantBits
        val lsb = uuid.leastSignificantBits
        for (i in 0 until 8) bytes[i] = (msb ushr (8 * (7 - i))).toByte()
        for (i in 0 until 8) bytes[8 + i] = (lsb ushr (8 * (7 - i))).toByte()
        return bytes
    }
}
