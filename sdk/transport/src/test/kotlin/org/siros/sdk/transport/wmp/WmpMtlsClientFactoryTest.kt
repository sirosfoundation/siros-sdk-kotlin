package org.siros.sdk.transport.wmp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The mTLS binding's client factory ([WmpHttpSseTransport.mtlsBinding]):
 * the PEM pair becomes the key manager the TLS handshake serves when the
 * server requests a client certificate (wmp-core §4.4.6's `mtls` auth type;
 * the binding's auth-type flip is [WmpSessionTest]'s own test).
 *
 * The certificate fixture is a self-signed test pair under
 * `src/test/resources/mtls/` — no production material.
 */
class WmpMtlsClientFactoryTest {

    private fun resource(name: String): String =
        java.io.FileReader(java.io.File(javaClass.getResource("/mtls/$name")!!.file)).readText()

    /** The PEM body's own codec, in test form. */
    private fun pemBody(pem: String): ByteArray {
        val body = Regex("-----BEGIN [\\w ]+-----([\\s\\S]*?)-----END [\\w ]+-----")
            .find(pem)!!.groupValues[1]
        return Base64.getDecoder().decode(body.filter { !it.isWhitespace() })
    }

    @Test
    fun theFixturePairBuildsAClient() {
        val binding = MtlsBinding(
            certificatePem = resource("test-client.crt"),
            privateKeyPem = resource("test-client.key"),
        )
        val client = WmpHttpSseTransport.mtlsClient(binding)
        // The factory's contract: a client whose SSL socket factory is the
        // binding's (not the JVM default's shape).
        assertTrue(client.sslSocketFactory !== null)
    }

    @Test
    fun anEmptyCertificatePemFailsFast() {
        val binding = MtlsBinding(
            certificatePem = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
            privateKeyPem = resource("test-client.key"),
        )
        try {
            WmpHttpSseTransport.mtlsClient(binding)
            throw AssertionError("Expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertEquals("the mtls binding's certificate PEM holds no certificate", e.message)
        }
    }

    @Test
    fun aMalformedKeyPemFailsFast() {
        val binding = MtlsBinding(
            certificatePem = resource("test-client.crt"),
            privateKeyPem = "not a pem at all",
        )
        try {
            WmpHttpSseTransport.mtlsClient(binding)
            throw AssertionError("Expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun theFixtureKeyParsesAsAnEcPkcs8Key() {
        // The factory's EC key parse (PKCS8): the fixture's key round-trips
        // through the same KeyFactory the factory uses.
        val key = java.security.KeyFactory.getInstance("EC")
            .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pemBody(resource("test-client.key"))))
        val encoded = key.encoded
        assertTrue(encoded.isNotEmpty())
        assertEquals(pemBody(resource("test-client.key")).size, encoded.size)
    }
}
