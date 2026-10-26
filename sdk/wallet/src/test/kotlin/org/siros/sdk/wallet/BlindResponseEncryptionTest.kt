// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The wallet-held response-encryption key of the engine-blind encryption contract (the JARM builder: sdk:keystore's AuthorizationResponseEncryptionTest). */
class BlindResponseEncryptionTest {

    /** What an issuer does: encrypt [plaintext] to the wallet's public JWK. */
    private fun issuerEncrypt(jwk: JsonObject, alg: String, enc: String, plaintext: String): String {
        val key = ECKey.parse(jwk.toString())
        val header = JWEHeader.Builder(JWEAlgorithm.parse(alg), EncryptionMethod.parse(enc)).build()
        val obj = JWEObject(header, Payload(plaintext))
        obj.encrypt(ECDHEncrypter(key))
        return obj.serialize()
    }

    private val algs = listOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")
    private val encs = listOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")

    @Test
    fun theKeyOpensAnIssuerJweForEveryNegotiableAlgAndEnc() {
        for (alg in algs) for (enc in encs) {
            val key = CredentialResponseKey.generate(alg, enc)!!
            val plaintext = """{"credentials":[{"credential":"c-$alg-$enc"}]}"""
            assertEquals("$alg/$enc", plaintext, key.decrypt(issuerEncrypt(key.publicJwk, alg, enc, plaintext)))
        }
    }

    @Test
    fun theAdvertisedPublicJwkIsAnEncryptionP256KeyWithoutTheirPrivatePart() {
        val jwk = CredentialResponseKey.generate("ECDH-ES+A256KW", "A128GCM")!!.publicJwk
        assertEquals("EC", jwk["kty"]!!.jsonPrimitive.content)
        assertEquals("P-256", jwk["crv"]!!.jsonPrimitive.content)
        assertEquals("enc", jwk["use"]!!.jsonPrimitive.content)
        assertEquals("ECDH-ES+A256KW", jwk["alg"]!!.jsonPrimitive.content)
        assertTrue(jwk.containsKey("x") && jwk.containsKey("y"))
        assertFalse("the private part must never leave the wallet", jwk.containsKey("d"))
        assertFalse(ECKey.parse(jwk.toString()).isPrivate)
    }

    @Test
    fun everyGenerateYieldsAFreshKey() {
        val a = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        val b = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        assertNotEquals(a.publicJwk, b.publicJwk)
        // A JWE for one key does not open under the other.
        val forA = issuerEncrypt(a.publicJwk, "ECDH-ES", "A256GCM", "x")
        assertThrows(IllegalArgumentException::class.java) { b.decrypt(forA) }
    }

    @Test
    fun aPairTheWalletCannotDecryptYieldsNoKey() {
        assertNull(CredentialResponseKey.generate("RSA-OAEP", "A128GCM"))
        assertNull(CredentialResponseKey.generate("ECDH-ES", "A128KW"))
        assertNull(CredentialResponseKey.generate("A256KW", "A256GCM"))
        assertNull(CredentialResponseKey.generate("dir", "A128GCM"))
    }

    @Test
    fun aResponseUsingAnotherPairThanTheNegotiatedOneIsRefused() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        val otherEnc = issuerEncrypt(key.publicJwk, "ECDH-ES", "A128GCM", "x")
        assertThrows(IllegalArgumentException::class.java) { key.decrypt(otherEnc) }
        val otherAlg = issuerEncrypt(key.publicJwk, "ECDH-ES+A256KW", "A256GCM", "x")
        assertThrows(IllegalArgumentException::class.java) { key.decrypt(otherAlg) }
    }

    @Test
    fun aValueThatIsNotACompactJweIsRefusedWithoutEchoingIt() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        for (bad in listOf("", "not-a-jwe", "a.b.c.d.e", """{"credentials":[]}""")) {
            val e = assertThrows(IllegalArgumentException::class.java) { key.decrypt(bad) }
            if (bad.isNotEmpty()) assertFalse(e.message!!.contains(bad))
        }
    }

    @Test
    fun aTamperedCiphertextIsRefused() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        val jwe = issuerEncrypt(key.publicJwk, "ECDH-ES", "A256GCM", "secret-credential")
        val parts = jwe.split(".").toMutableList()
        parts[3] = parts[3].reversed()
        val e = assertThrows(IllegalArgumentException::class.java) { key.decrypt(parts.joinToString(".")) }
        assertFalse(e.message!!.contains("secret-credential"))
    }

    @Test
    fun theKeyPrintsNothing() {
        val key = CredentialResponseKey.generate("ECDH-ES", "A256GCM")!!
        assertFalse(key.toString().contains(key.publicJwk["x"]!!.jsonPrimitive.content))
    }

    @Test
    fun theAdvertisedJwkHasExactlyTheMembersTheEngineAccepts() {
        for (alg in algs) {
            val jwk = CredentialResponseKey.generate(alg, "A128GCM")!!.publicJwk
            assertEquals(setOf("kty", "crv", "x", "y", "use", "alg"), jwk.keys)
            assertEquals(alg, jwk["alg"]!!.jsonPrimitive.content)
        }
    }
}
