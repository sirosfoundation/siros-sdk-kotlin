package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientIdSchemeTest {

    @Test
    fun `parse x509_san_dns`() {
        val result = ClientIdScheme.parse("x509_san_dns:verifier.example.com")
        assertTrue(result is ClientIdScheme.X509SanDns)
        assertEquals("verifier.example.com", result.identifier)
    }

    @Test
    fun `parse x509_san_uri`() {
        val result = ClientIdScheme.parse("x509_san_uri:https://verifier.example.com/callback")
        assertTrue(result is ClientIdScheme.X509SanUri)
        assertEquals("https://verifier.example.com/callback", result.identifier)
    }

    @Test
    fun `parse did web`() {
        val result = ClientIdScheme.parse("did:web:verifier.example.com")
        assertTrue(result is ClientIdScheme.Did)
        assertEquals("did:web:verifier.example.com", result.identifier)
        assertEquals("web", (result as ClientIdScheme.Did).method)
    }

    @Test
    fun `parse did webvh`() {
        val result = ClientIdScheme.parse("did:webvh:verifier.example.com")
        assertTrue(result is ClientIdScheme.Did)
        assertEquals("webvh", (result as ClientIdScheme.Did).method)
    }

    @Test
    fun `parse verifier_attestation`() {
        val result = ClientIdScheme.parse("verifier_attestation:verifier.example")
        assertTrue(result is ClientIdScheme.VerifierAttestation)
        assertEquals("verifier.example", result.identifier)
    }

    @Test
    fun `parse https url`() {
        val result = ClientIdScheme.parse("https://verifier.example.com")
        assertTrue(result is ClientIdScheme.Https)
        assertEquals("https://verifier.example.com", result.identifier)
    }

    @Test
    fun `parse pre-registered fallback`() {
        val result = ClientIdScheme.parse("my-registered-client")
        assertTrue(result is ClientIdScheme.PreRegistered)
        assertEquals("my-registered-client", result.identifier)
    }

    @Test
    fun `TrustResult parsedScheme derives from identifier`() {
        val trustResult = TrustResult(
            trusted = true,
            identifier = "x509_san_dns:example.com",
        )
        val scheme = trustResult.parsedScheme
        assertTrue(scheme is ClientIdScheme.X509SanDns)
        assertEquals("example.com", scheme?.identifier)
    }

    @Test
    fun `TrustResult parsedScheme is null when identifier is null`() {
        val trustResult = TrustResult(trusted = true, identifier = null)
        assertEquals(null, trustResult.parsedScheme)
    }
}
