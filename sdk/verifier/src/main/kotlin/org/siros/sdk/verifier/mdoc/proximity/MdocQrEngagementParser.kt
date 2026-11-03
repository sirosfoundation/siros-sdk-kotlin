// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID

/**
 * Strict parser for ISO 18013-5 §8.2.2.3 `mdoc:` QR device engagement.
 *
 * This foundation supports DeviceEngagement 1.0, cipher suite 1, and BLE
 * retrieval method version 1. NFC/Wi-Fi-aware retrieval and later versions are
 * rejected rather than guessed at. Non-minimal (but well-formed) integer and
 * tag encodings are accepted and their original bytes are retained; the parser
 * never re-encodes values for the session transcript or `computeIdent`.
 */
object MdocQrEngagementParser {
    /** Maximum decoded DeviceEngagement size accepted by [parse]. */
    const val MAX_DEVICE_ENGAGEMENT_BYTES: Int = 16 * 1024

    private const val PREFIX = "mdoc:"
    private val MAX_ENCODED_LENGTH = (4 * MAX_DEVICE_ENGAGEMENT_BYTES + 2) / 3
    private val MIN_LONG = BigInteger.valueOf(Long.MIN_VALUE)
    private val MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE)
    private val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()

    /**
     * Parses an unpadded-base64url `mdoc:` URI.
     *
     * @throws MdocEngagementParseException for malformed or unsupported input.
     */
    @JvmStatic
    fun parse(mdocUri: String): MdocQrEngagement {
        if (mdocUri.length > PREFIX.length + MAX_ENCODED_LENGTH) {
            invalid("DeviceEngagement exceeds $MAX_DEVICE_ENGAGEMENT_BYTES bytes")
        }
        if (!mdocUri.startsWith(PREFIX)) invalid("QR engagement must use the mdoc: scheme")
        val encoded = mdocUri.substring(PREFIX.length)
        if (encoded.any { it !in 'A'..'Z' && it !in 'a'..'z' && it !in '0'..'9' && it != '-' && it != '_' }) {
            invalid("DeviceEngagement is not unpadded base64url")
        }
        val bytes = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw MdocEngagementParseException("DeviceEngagement is not valid base64url", e)
        }
        if (bytes.size > MAX_DEVICE_ENGAGEMENT_BYTES) {
            invalid("DeviceEngagement exceeds $MAX_DEVICE_ENGAGEMENT_BYTES bytes")
        }
        // The decoder accepts non-zero unused bits in the final symbol. Those
        // have multiple textual forms and are not the canonical QR encoding.
        if (base64UrlEncoder.encodeToString(bytes) != encoded) {
            invalid("DeviceEngagement is not canonical unpadded base64url")
        }

        val decoded = decode(bytes, "DeviceEngagement")
        val engagement = decoded as? CborValue.Map ?: invalid("DeviceEngagement must be an untagged map")
        requireOnlyKeys(engagement, setOf(0L, 1L, 2L), "DeviceEngagement")

        val version = requiredMember(engagement, 0L, "DeviceEngagement.version") as? CborValue.Text
            ?: invalid("DeviceEngagement.version must be a text string")
        if (version.value != "1.0") invalid("Unsupported DeviceEngagement version: ${version.value}")

        val security = requiredMember(engagement, 1L, "DeviceEngagement.security") as? CborValue.Array
            ?: invalid("DeviceEngagement.security must be an array")
        if (security.items.size != 2) invalid("DeviceEngagement.security must contain exactly two items")
        if (security.items[0].longOrNull("cipher suite") != 1L) {
            invalid("Only DeviceEngagement cipher suite 1 is supported")
        }
        val eDeviceKey = security.items[1]
        validateEDeviceKey(eDeviceKey)

        val retrievalMethods = optionalMember(engagement, 2L)
        val ble = retrievalMethods?.let(::parseRetrievalMethods)

        return MdocQrEngagement(
            deviceEngagementBytes = bytes.copyOf(),
            eDeviceKeyBytes = bytes.copyOfRange(eDeviceKey.start, eDeviceKey.end),
            qrHandover = byteArrayOf(0xf6.toByte()),
            ble = ble,
        )
    }

    private fun validateEDeviceKey(value: CborValue) {
        val tagged = value as? CborValue.Tag
            ?: invalid("Security.EDeviceKeyBytes must be tag-24 wrapped")
        if (tagged.tag != BigInteger.valueOf(24)) {
            invalid("Security.EDeviceKeyBytes must use CBOR tag 24")
        }
        val keyBytes = tagged.item as? CborValue.Bytes
            ?: invalid("Security.EDeviceKeyBytes must contain a byte string")
        val coseKey = decode(keyBytes.value, "EDeviceKey") as? CborValue.Map
            ?: invalid("EDeviceKey must be a COSE_Key map")

        if (requiredMember(coseKey, 1L, "COSE_Key.kty").longOrNull("COSE_Key.kty") != 2L) {
            invalid("EDeviceKey must use COSE key type EC2")
        }
        if (requiredMember(coseKey, -1L, "COSE_Key.crv").longOrNull("COSE_Key.crv") != 1L) {
            invalid("EDeviceKey must use the P-256 curve")
        }
        requireCoordinate(coseKey, -2L, "x")
        requireCoordinate(coseKey, -3L, "y")
    }

    private fun requireCoordinate(coseKey: CborValue.Map, label: Long, name: String) {
        val coordinate = requiredMember(coseKey, label, "COSE_Key.$name") as? CborValue.Bytes
            ?: invalid("COSE_Key.$name must be a byte string")
        if (coordinate.value.size != 32) invalid("COSE_Key.$name must contain exactly 32 bytes")
    }

    private fun parseRetrievalMethods(value: CborValue): BleDeviceRetrievalMethod {
        val methods = value as? CborValue.Array
            ?: invalid("DeviceEngagement.deviceRetrievalMethods must be an array")
        if (methods.items.size != 1) {
            invalid("Exactly one BLE device retrieval method is required when retrieval methods are present")
        }
        val method = methods.items[0] as? CborValue.Array
            ?: invalid("DeviceRetrievalMethod must be an array")
        if (method.items.size != 3) invalid("DeviceRetrievalMethod must contain exactly three items")
        if (method.items[0].longOrNull("retrieval method type") != 2L) {
            invalid("Only BLE device retrieval method type 2 is supported")
        }
        if (method.items[1].longOrNull("retrieval method version") != 1L) {
            invalid("Only BLE device retrieval method version 1 is supported")
        }
        return parseBleOptions(method.items[2])
    }

    private fun parseBleOptions(value: CborValue): BleDeviceRetrievalMethod {
        val options = value as? CborValue.Map ?: invalid("BleOptions must be a map")
        requireOnlyKeys(options, setOf(0L, 1L, 10L, 11L), "BleOptions")

        val peripheral = requiredMember(options, 0L, "BleOptions.supportsPeripheralServerMode") as? CborValue.Boolean
            ?: invalid("BleOptions.supportsPeripheralServerMode must be a boolean")
        val central = requiredMember(options, 1L, "BleOptions.supportsCentralClientMode") as? CborValue.Boolean
            ?: invalid("BleOptions.supportsCentralClientMode must be a boolean")
        if (!peripheral.value && !central.value) invalid("BleOptions must enable at least one BLE mode")

        val peripheralBytes = optionalUuidBytes(options, 10L, "peripheralServerModeUUID")
        val centralBytes = optionalUuidBytes(options, 11L, "centralClientModeUUID")
        if (peripheral.value != (peripheralBytes != null)) {
            invalid("BleOptions peripheral-server flag and UUID are inconsistent")
        }
        if (central.value != (centralBytes != null)) {
            invalid("BleOptions central-client flag and UUID are inconsistent")
        }

        return BleDeviceRetrievalMethod(
            supportsPeripheralServerMode = peripheral.value,
            supportsCentralClientMode = central.value,
            peripheralServerModeUuid = peripheralBytes?.let(::uuid),
            centralClientModeUuid = centralBytes?.let(::uuid),
        )
    }

    private fun optionalUuidBytes(options: CborValue.Map, key: Long, name: String): ByteArray? {
        val value = optionalMember(options, key) ?: return null
        val bytes = value as? CborValue.Bytes ?: invalid("BleOptions.$name must be a byte string")
        if (bytes.value.size != 16) invalid("BleOptions.$name must contain exactly 16 bytes")
        return bytes.value
    }

    private fun uuid(bytes: ByteArray): UUID {
        val buffer = ByteBuffer.wrap(bytes)
        return UUID(buffer.long, buffer.long)
    }

    private fun decode(bytes: ByteArray, name: String): CborValue = try {
        StrictCbor.decode(bytes)
    } catch (e: CborDecodeException) {
        throw MdocEngagementParseException("Malformed $name CBOR: ${e.message}", e)
    }

    private fun requireOnlyKeys(map: CborValue.Map, allowed: Set<Long>, name: String) {
        val allowedIntegers = allowed.map { BigInteger.valueOf(it) }
        if (map.entries.any { entry ->
                val key = entry.key as? CborValue.Integer
                key == null || key.value !in allowedIntegers
            }
        ) {
            invalid("$name contains an unsupported map key")
        }
    }

    private fun requiredMember(map: CborValue.Map, key: Long, name: String): CborValue =
        optionalMember(map, key) ?: invalid("$name is required")

    private fun optionalMember(map: CborValue.Map, key: Long): CborValue? {
        val integerKey = BigInteger.valueOf(key)
        return map.entries.firstOrNull {
            (it.key as? CborValue.Integer)?.value == integerKey
        }?.value
    }

    private fun CborValue.longOrNull(name: String): Long? {
        val integer = this as? CborValue.Integer ?: invalid("$name must be an integer")
        if (integer.value < MIN_LONG || integer.value > MAX_LONG) {
            invalid("$name is outside the supported integer range")
        }
        return integer.value.toLong()
    }

    private fun invalid(message: String): Nothing = throw MdocEngagementParseException(message)
}
