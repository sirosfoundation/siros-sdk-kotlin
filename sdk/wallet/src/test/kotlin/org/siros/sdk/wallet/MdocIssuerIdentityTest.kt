package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Fixtures are self-signed certificates generated with openssl, one per SAN
 * shape (see the file names); `openssl x509 -in <f> -noout -ext
 * subjectAltName` shows each one's names.
 */
class MdocIssuerIdentityTest {

    private fun cert(name: String): X509Certificate {
        val pem = checkNotNull(javaClass.getResourceAsStream("/mdoc-issuer-identity/$name.pem")) { "missing fixture $name" }
        return CertificateFactory.getInstance("X.509").generateCertificate(pem) as X509Certificate
    }

    @Test
    fun `an https URI SAN wins over DNS SANs, whatever their order`() {
        // SAN = DNS:localhost, DNS:vc-issuer, URI:https://issuer.example/tenant -
        // the shape of sirosid-dev's signing certificate since sirosid-dev#39.
        // Under a first-DNS-SAN rule this would be "https://localhost", which
        // is exactly what made every deployed mDL look untrusted.
        assertEquals("https://issuer.example/tenant", MdocIssuerIdentity.fromCertificate(cert("uri_and_dns")))
    }

    @Test
    fun `an http URI SAN is lifted to https`() {
        // SAN = URI:http://issuer.example, DNS:localhost
        assertEquals("https://issuer.example", MdocIssuerIdentity.fromCertificate(cert("http_uri")))
    }

    @Test
    fun `without a URI SAN the first non-wildcard DNS SAN names the issuer`() {
        // SAN = DNS:*.example.org, DNS:issuer.example.org
        assertEquals("https://issuer.example.org", MdocIssuerIdentity.fromCertificate(cert("dns_only")))
    }

    @Test
    fun `a wildcard DNS SAN alone names nothing`() {
        assertNull(MdocIssuerIdentity.fromCertificate(cert("wildcard_only")))
    }

    @Test
    fun `no SAN extension names nothing`() {
        assertNull(MdocIssuerIdentity.fromCertificate(cert("no_san")))
    }

    @Test
    fun `fromDer parses the certificate and unparseable bytes name nothing`() {
        assertEquals("https://issuer.example/tenant", MdocIssuerIdentity.fromDer(cert("uri_and_dns").encoded))
        assertNull(MdocIssuerIdentity.fromDer(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)))
    }
}
