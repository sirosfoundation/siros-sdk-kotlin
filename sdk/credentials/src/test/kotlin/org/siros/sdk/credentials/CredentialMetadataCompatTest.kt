// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [CredentialMetadata] is persisted as JSON inside the keystore for the
 * lifetime of a session, so a field added to it must never break decoding of
 * what an earlier build wrote - and the fallback marker must not leak into
 * what a build without it would misread.
 */
class CredentialMetadataCompatTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** Exactly what a pre-`hydration` build serialised for a real, VCTM-derived record. */
    private val legacyStoredCredentialJson = """
        {
          "id": 123456,
          "format": "dc+sd-jwt",
          "raw": "eyJhbGciOiJFUzI1NiJ9.e30.sig~",
          "batch_id": 1700000000000,
          "instance_id": 0,
          "metadata": {
            "name": "Personal ID",
            "issuer": { "name": "Example Issuer", "url": "https://issuer.example.com" },
            "vct": "urn:eudi:pid:1",
            "background_color": "#003366",
            "text_color": "#ffffff",
            "logo": { "uri": "https://issuer.example.com/logo.png" },
            "claims": [ { "path": ["given_name"], "label": "Given name" } ],
            "svg_templates": [ { "uri": "https://issuer.example.com/card.svg", "color_scheme": "light" } ]
          }
        }
    """.trimIndent()

    @Test
    fun `stored JSON written before the hydration field decodes unchanged and is not a fallback`() {
        val cred = json.decodeFromString(StoredCredential.serializer(), legacyStoredCredentialJson)
        val meta = cred.metadata!!
        assertNull(meta.hydration)
        assertFalse(meta.isFallback)
        assertEquals("Personal ID", meta.name)
        assertEquals("urn:eudi:pid:1", meta.vct)
        assertEquals(1, meta.svgTemplates!!.size)
        assertEquals("Given name", meta.claims!!.single().label)
    }

    @Test
    fun `fallback metadata round-trips with its marker and nothing else made up`() {
        val cred = StoredCredential(
            id = 1,
            format = "dc+sd-jwt",
            // header.payload(vct only).sig - payload is {"vct":"urn:eudi:pid:1"}
            raw = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSJ9.c2ln~",
            batchId = 1,
            instanceId = 0,
            credentialIssuerIdentifier = "https://issuer.example.com/tenant-a",
            credentialConfigurationId = "eu.europa.ec.eudi.pid_sd_jwt",
        )
        val meta = CredentialUtils.buildFallbackMetadata(cred)
        assertTrue(meta.isFallback)
        assertEquals("Pid Sd Jwt", meta.name)
        assertEquals("issuer.example.com", meta.issuer!!.name)
        assertEquals("https://issuer.example.com/tenant-a", meta.issuer!!.url)
        assertEquals("urn:eudi:pid:1", meta.vct)
        assertNull(meta.logo)
        assertNull(meta.svgTemplates)
        assertNull(meta.backgroundColor)

        val encoded = json.encodeToString(CredentialMetadata.serializer(), meta)
        val obj = json.parseToJsonElement(encoded).jsonObject
        assertEquals("\"fallback\"", obj["hydration"].toString())
        // `isFallback` is derived, never serialised.
        assertNull(obj["isFallback"])
        val decoded = json.decodeFromString(CredentialMetadata.serializer(), encoded)
        assertEquals(meta, decoded)
    }

    @Test
    fun `fallback for a credential missing issuer and configuration falls back to the format`() {
        val cred = StoredCredential(id = 2, format = "mso_mdoc", raw = "", batchId = 1, instanceId = 0)
        val meta = CredentialUtils.buildFallbackMetadata(cred)
        assertTrue(meta.isFallback)
        assertEquals("mso_mdoc", meta.name)
        assertNull(meta.issuer!!.name)
        assertNull(meta.issuer!!.url)
    }
}
