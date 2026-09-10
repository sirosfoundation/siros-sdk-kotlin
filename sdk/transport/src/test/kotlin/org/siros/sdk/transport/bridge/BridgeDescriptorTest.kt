// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.bridge

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The descriptor is the wire contract between a wrapper app and the page
 * (its TypeScript twin is generated from the same spec), so these pin the
 * JSON shape rather than the Kotlin API: the page only ever sees the JSON.
 */
class BridgeDescriptorTest {

    private val host = BridgeHost(name = "org.siros.wwwallet", version = "3.1.0", sdkVersion = "0.15.0")

    @Test
    fun `descriptor carries versions, host and only the offered capabilities`() {
        val json = BridgeDescriptorBuilder(platform = "android", host = host)
            .zk(ZkCapability(systems = listOf("longfellow-libzk-v1"), circuitCache = true))
            .proximitySession(ProximitySessionCapability(transports = listOf("ble_peripheral"), nfcStaticHandover = true))
            .oidc()
            .encode()

        val root = Json.parseToJsonElement(json).jsonObject
        assertEquals(BridgeVocabulary.DESCRIPTOR_VERSION, root["bridge"]!!.jsonObject["version"]!!.jsonPrimitive.content.toInt())
        assertEquals(BridgeVocabulary.VERSION, root["vocabulary"]!!.jsonPrimitive.content.toInt())
        assertEquals("android", root["platform"]!!.jsonPrimitive.content)
        assertEquals("0.15.0", root["host"]!!.jsonObject["sdk_version"]!!.jsonPrimitive.content)

        val caps = root["capabilities"]!!.jsonObject
        assertEquals(setOf("zk", "proximity.session", "oidc"), caps.keys)
        assertEquals("longfellow-libzk-v1", caps["zk"]!!.jsonObject["systems"]!!.jsonArray.single().jsonPrimitive.content)
        assertEquals("true", caps["proximity.session"]!!.jsonObject["nfc_static_handover"]!!.jsonPrimitive.content)
        // A capability with no parameters is an empty object, not null - presence is the signal.
        assertTrue(caps["oidc"]!!.jsonObject.isEmpty())
        // Unset parameters are omitted, not emitted as null.
        assertNull(caps["proximity.session"]!!.jsonObject["reader_auth"])
    }

    @Test
    fun `ids are stable strings and the deprecated map names only retired ones`() {
        assertEquals("idv.physical_id", BridgeCapabilityId.IDV_PHYSICAL_ID)
        assertEquals(BridgeCapabilityId.ALL.size, BridgeCapabilityId.ALL.toSet().size)
        assertTrue(BridgeCapabilityId.DEPRECATED.keys.all { it in BridgeCapabilityId.ALL })
        assertTrue(BridgeCapabilityId.PROXIMITY_BYTE_PIPE in BridgeCapabilityId.DEPRECATED)
        assertFalse(BridgeCapabilityId.PROXIMITY_SESSION in BridgeCapabilityId.DEPRECATED)
    }

    @Test
    fun `descriptor round-trips through the serializer`() {
        val built = BridgeDescriptorBuilder(platform = "ios", host = host)
            .webauthn(WebauthnCapability(prf = true, securityKeyTransports = listOf("nfc", "usb")))
            .build()
        val json = Json { encodeDefaults = true; explicitNulls = false }
        val decoded = json.decodeFromString(BridgeDescriptor.serializer(), json.encodeToString(BridgeDescriptor.serializer(), built))
        assertEquals(built, decoded)
        val webauthn = json.decodeFromJsonElement(WebauthnCapability.serializer(), decoded.capabilities["webauthn"]!!)
        assertEquals(listOf("nfc", "usb"), webauthn.securityKeyTransports)
    }
}
