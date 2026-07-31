// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class DCAPIRequestParserTest {

    @Test
    fun `unwraps the requests envelope for an unsigned request`() {
        val rawRequestJson = """
            {"requests":[{"protocol":"openid4vp-v1-unsigned","data":{
                "client_id":"web-origin:https://verifier.example.com",
                "response_mode":"dc_api",
                "nonce":"test-nonce",
                "dcql_query":{"credentials":[]}
            }}]}
        """.trimIndent()

        val result = DCAPIRequestParser.parse(rawRequestJson)

        assertEquals("web-origin:https://verifier.example.com", result.clientId)
        assertEquals("dc_api", result.responseMode)
        assertEquals("test-nonce", result.nonce)
        assertNull(result.keyMaterial)
    }

    @Test
    fun `unwraps the requests envelope for a signed request`() {
        val ecKey = ECKeyGenerator(Curve.P_256).generate()
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", "x509_san_dns:verifier.example.com")
            .claim("response_mode", "dc_api.jwt")
            .claim("nonce", "test-nonce")
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build()
        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(ECDSASigner(ecKey))
        val jwt = signedJwt.serialize()

        val rawRequestJson = """{"requests":[{"protocol":"openid4vp-v1-signed","data":{"request":"$jwt"}}]}"""

        val result = DCAPIRequestParser.parse(rawRequestJson)

        assertEquals("x509_san_dns:verifier.example.com", result.clientId)
        assertEquals("dc_api.jwt", result.responseMode)
        assertEquals("test-nonce", result.nonce)
        assertEquals(ecKey.keyID, result.keyMaterial?.jwk?.get("kid")?.toString()?.trim('"'))
    }

    @Test
    fun `throws when the requests array is missing`() {
        val exception = assertThrows(DCAPIRequestException::class.java) {
            DCAPIRequestParser.parse("""{"client_id":"x"}""")
        }
        assertEquals("DC API request missing 'requests' array", exception.message)
    }

    @Test
    fun `throws when the requests array is empty`() {
        val exception = assertThrows(DCAPIRequestException::class.java) {
            DCAPIRequestParser.parse("""{"requests":[]}""")
        }
        assertEquals("DC API request's 'requests' array is empty", exception.message)
    }

    @Test
    fun `throws when the first entry has no data`() {
        val exception = assertThrows(DCAPIRequestException::class.java) {
            DCAPIRequestParser.parse("""{"requests":[{"protocol":"openid4vp-v1-unsigned"}]}""")
        }
        assertEquals("DC API request's first entry is missing 'data'", exception.message)
    }
}
