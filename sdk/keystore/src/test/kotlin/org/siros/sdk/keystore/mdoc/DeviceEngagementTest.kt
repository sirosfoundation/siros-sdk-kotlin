// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Structural conformance tests against ISO 18013-5 §8.2.1.1's `DeviceEngagement`
 * CDDL (map keys 0/1/2, `Security` array shape, tag-24-wrapped `EDeviceKeyBytes`,
 * `BleOptions` key numbers). Verified against the shape of Annex D.3.1's worked
 * example, not its exact byte values - the example's hex was only available via
 * OCR'd PDF text in this session and wasn't trustworthy enough to hardcode as a
 * byte-exact fixture (canonical map-key ordering isn't required by the spec
 * anyway, so a byte-exact comparison against a fresh keypair wouldn't be
 * meaningful regardless). A clean copy of the official vector should replace
 * this with real byte-exact assertions when available.
 */
class DeviceEngagementTest {

    @Test
    fun create_bothBleModes_producesSpecShapedStructure() {
        val engagement = DeviceEngagement.create(
            supportsCentralClientMode = true,
            supportsPeripheralServerMode = true,
        )

        val decoded = CBORObject.DecodeFromBytes(engagement.deviceEngagementBytes)
        assertEquals(CBORType.Map, decoded.type)
        assertEquals("1.0", decoded[CBORObject.FromObject(0L)].AsString())

        val security = decoded[CBORObject.FromObject(1L)]
        assertEquals(CBORType.Array, security.type)
        assertEquals(2, security.size())
        assertEquals(1L, security[0].AsInt64Value())
        val eDeviceKeyBytes = security[1]
        assertTrue(eDeviceKeyBytes.HasOneTag(24))
        val coseKey = CBORObject.DecodeFromBytes(eDeviceKeyBytes.UntagOne().GetByteString())
        assertEquals(2L, coseKey[CBORObject.FromObject(1L)].AsInt64Value()) // kty = EC2
        assertEquals(1L, coseKey[CBORObject.FromObject(-1L)].AsInt64Value()) // crv = P-256
        assertArrayEquals(
            padTo32(engagement.publicKey.w.affineX.toByteArray()),
            coseKey[CBORObject.FromObject(-2L)].GetByteString(),
        )
        assertArrayEquals(
            padTo32(engagement.publicKey.w.affineY.toByteArray()),
            coseKey[CBORObject.FromObject(-3L)].GetByteString(),
        )

        val retrievalMethods = decoded[CBORObject.FromObject(2L)]
        assertEquals(CBORType.Array, retrievalMethods.type)
        assertEquals(1, retrievalMethods.size())
        val ble = retrievalMethods[0]
        assertEquals(2L, ble[0].AsInt64Value()) // type = BLE
        assertEquals(1L, ble[1].AsInt64Value()) // version
        val bleOptions = ble[2]
        assertTrue(bleOptions[CBORObject.FromObject(0L)].AsBoolean())
        assertTrue(bleOptions[CBORObject.FromObject(1L)].AsBoolean())
        assertEquals(16, bleOptions[CBORObject.FromObject(10L)].GetByteString().size)
        assertEquals(16, bleOptions[CBORObject.FromObject(11L)].GetByteString().size)
    }

    @Test
    fun create_centralOnly_omitsPeripheralUuidAndSetsFlagsCorrectly() {
        val engagement = DeviceEngagement.create(
            supportsCentralClientMode = true,
            supportsPeripheralServerMode = false,
        )

        assertNull(engagement.peripheralServerModeUuid)
        val decoded = CBORObject.DecodeFromBytes(engagement.deviceEngagementBytes)
        val bleOptions = decoded[CBORObject.FromObject(2L)][0][2]
        assertFalse(bleOptions[CBORObject.FromObject(0L)].AsBoolean())
        assertTrue(bleOptions[CBORObject.FromObject(1L)].AsBoolean())
        assertNull(bleOptions[CBORObject.FromObject(10L)])
        assertEquals(16, bleOptions[CBORObject.FromObject(11L)].GetByteString().size)
    }

    @Test
    fun create_neitherBleMode_throws() {
        try {
            DeviceEngagement.create(supportsCentralClientMode = false, supportsPeripheralServerMode = false)
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun mdocUri_isMdocSchemePrefixedBase64UrlWithoutPadding() {
        val engagement = DeviceEngagement.create()

        assertTrue(engagement.mdocUri.startsWith("mdoc:"))
        val encoded = engagement.mdocUri.removePrefix("mdoc:")
        assertFalse("must not contain padding", encoded.contains("="))
        val decodedBytes = Base64.getUrlDecoder().decode(encoded)
        assertArrayEquals(engagement.deviceEngagementBytes, decodedBytes)
    }

    @Test
    fun create_generatesFreshKeyAndUuidsPerCall() {
        val first = DeviceEngagement.create()
        val second = DeviceEngagement.create()

        assertFalse(first.deviceEngagementBytes.contentEquals(second.deviceEngagementBytes))
        assertFalse(first.centralClientModeUuid == second.centralClientModeUuid)
    }

    private fun padTo32(bytes: ByteArray): ByteArray = when {
        bytes.size == 32 -> bytes
        bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
        else -> ByteArray(32 - bytes.size) + bytes
    }
}
