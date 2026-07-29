// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DCAPIResponseEncryptionTest {

    @Test
    fun encryptResponse_roundTripsWithMatchingPrivateKey() {
        val verifierKeyPair = ECKeyGenerator(Curve.P_256).generate()
        val payload = """{"vp_token":{"query1":"eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidHJ1ZSJ9.sig"}}"""

        val jwe = DCAPIResponseEncryption.encryptResponse(
            responseJson = payload,
            verifierJwk = verifierKeyPair.toPublicJWK(),
        )

        val parsed = JWEObject.parse(jwe)
        assertEquals(JWEAlgorithm.ECDH_ES, parsed.header.algorithm)
        assertEquals(EncryptionMethod.A128GCM, parsed.header.encryptionMethod)

        parsed.decrypt(ECDHDecrypter(verifierKeyPair))
        assertEquals(payload, parsed.payload.toString())
    }

    @Test
    fun encryptResponse_supportsOverriddenAlgAndEnc() {
        val verifierKeyPair = ECKeyGenerator(Curve.P_256).generate()
        val payload = """{"vp_token":{}}"""

        val jwe = DCAPIResponseEncryption.encryptResponse(
            responseJson = payload,
            verifierJwk = verifierKeyPair.toPublicJWK(),
            alg = JWEAlgorithm.ECDH_ES_A256KW,
            enc = EncryptionMethod.A256GCM,
        )

        val parsed = JWEObject.parse(jwe)
        assertEquals(JWEAlgorithm.ECDH_ES_A256KW, parsed.header.algorithm)
        assertEquals(EncryptionMethod.A256GCM, parsed.header.encryptionMethod)
        parsed.decrypt(ECDHDecrypter(verifierKeyPair))
        assertEquals(payload, parsed.payload.toString())
    }

    @Test
    fun encryptResponse_rejectsNonECVerifierKey() {
        val rsaKey: RSAKey = RSAKeyGenerator(2048).generate()
        assertThrows(IllegalArgumentException::class.java) {
            DCAPIResponseEncryption.encryptResponse(
                responseJson = "{}",
                verifierJwk = rsaKey.toPublicJWK(),
            )
        }
    }
}
