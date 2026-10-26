// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The OpenID4VP `direct_post.jwt` (JARM) builder and the engine's conformance rules for `response_jwe` (moved from sdk:wallet's BlindResponseEncryptionTest). */
class AuthorizationResponseEncryptionTest {

    private val algs = listOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")
    private val encs = listOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")

    // ---- JARM ----

    private val verifier: ECKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).keyID("verifier-key-1").generate()
    private fun publicJwk(k: ECKey): JsonObject = Json.parseToJsonElement(k.toPublicJWK().toJSONString()).jsonObject

    private fun decryptJarm(jwe: String, key: ECKey = verifier): Pair<JWEHeader, JsonObject> {
        val obj = JWEObject.parse(jwe)
        obj.decrypt(ECDHDecrypter(key))
        return obj.header to Json.parseToJsonElement(obj.payload.toString()).jsonObject
    }

    @Test
    fun theJarmResponseDecryptsAtTheVerifierWithTheContractClaimsAndHeader() {
        val vpToken = buildJsonObject { put("pid", JsonArray(listOf(JsonPrimitive("tok-1")))) }
        val jwe = AuthorizationResponseEncryption.encrypt(
            vpToken, "x509_san_dns:verifier.example", "state-123", publicJwk(verifier), "ECDH-ES", "A128GCM", nowSeconds = 1_700_000_000,
        )
        val (header, claims) = decryptJarm(jwe)
        assertEquals("ECDH-ES", header.algorithm.name)
        assertEquals("A128GCM", header.encryptionMethod.name)
        assertEquals("verifier-key-1", header.keyID)
        // The plaintext is plain JSON claims, not a nested JWT: no cty (RFC 7519 section 5.2).
        assertNull(header.contentType)
        assertEquals("https://self-issued.me/v2", claims["iss"]!!.jsonPrimitive.content)
        assertEquals("x509_san_dns:verifier.example", claims["aud"]!!.jsonPrimitive.content)
        assertEquals(1_700_000_000L, claims["iat"]!!.jsonPrimitive.content.toLong())
        assertEquals(1_700_000_300L, claims["exp"]!!.jsonPrimitive.content.toLong())
        assertEquals("state-123", claims["state"]!!.jsonPrimitive.content)
        assertEquals(vpToken, claims["vp_token"])
    }

    @Test
    fun theJarmResponseOmitsStateWhenTheRequestHadNone() {
        for (state in listOf(null, "")) {
            val jwe = AuthorizationResponseEncryption.encrypt(JsonPrimitive("tok"), "aud", state, publicJwk(verifier), "ECDH-ES", "A128GCM")
            val claims = decryptJarm(jwe).second
            assertFalse(claims.containsKey("state"))
            assertEquals("tok", claims["vp_token"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun theJarmResponseHonoursTheRequestedAlgAndEnc() {
        for ((alg, enc) in listOf("ECDH-ES+A256KW" to "A256GCM", "ECDH-ES" to "A128CBC-HS256", "ECDH-ES+A128KW" to "A256CBC-HS512")) {
            val header = decryptJarm(AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, publicJwk(verifier), alg, enc)).first
            assertEquals(alg, header.algorithm.name)
            assertEquals(enc, header.encryptionMethod.name)
        }
    }

    @Test
    fun theJarmResponseCanBeEncryptedToAnRsaVerifierKey() {
        val rsa = RSAKeyGenerator(2048).keyUse(KeyUse.ENCRYPTION).keyID("rsa-1").generate()
        val jwe = AuthorizationResponseEncryption.encrypt(
            JsonPrimitive("tok"), "aud", "s", Json.parseToJsonElement(rsa.toPublicJWK().toJSONString()).jsonObject, "RSA-OAEP-256", "A128GCM",
        )
        val obj = JWEObject.parse(jwe)
        obj.decrypt(RSADecrypter(rsa as RSAKey))
        assertEquals("tok", Json.parseToJsonElement(obj.payload.toString()).jsonObject["vp_token"]!!.jsonPrimitive.content)
        assertEquals("rsa-1", obj.header.keyID)
    }

    @Test
    fun theJarmBuilderRefusesAPrivateKeyAnUnknownPairAndAGarbageJwk() {
        val priv = Json.parseToJsonElement(verifier.toJSONString()).jsonObject
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, priv, "ECDH-ES", "A128GCM")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, publicJwk(verifier), "ECDH-ES", "NOPE")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, buildJsonObject { put("kty", JsonPrimitive("EC")) }, "ECDH-ES", "A128GCM")
        }
        // An EC key cannot take an RSA key-management algorithm.
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encrypt(JsonPrimitive("t"), "a", null, publicJwk(verifier), "RSA-OAEP", "A128GCM")
        }
    }

    @Test
    fun theJarmJweCarriesNoPlaintextToken() {
        // Characters outside the base64url alphabet, so the check cannot collide with valid JWE output by chance.
        val sentinel = "very secret vp token! \u2713"
        val jwe = AuthorizationResponseEncryption.encrypt(JsonPrimitive(sentinel), "aud", null, publicJwk(verifier), "ECDH-ES", "A128GCM")
        assertFalse(jwe.contains(sentinel))
        assertEquals(sentinel, decryptJarm(jwe).second["vp_token"]!!.jsonPrimitive.content)
    }

    // ---- the engine's conformance rules for response_jwe (go-wallet-backend#471) ----

    private fun jarm(alg: String, enc: String, key: JsonObject = publicJwk(verifier), vp: kotlinx.serialization.json.JsonElement = JsonPrimitive("t")) =
        AuthorizationResponseEncryption.encrypt(vp, "aud", "s", key, alg, enc)

    @Test
    fun everyJarmResponseIsFiveNonEmptySegmentsWithTheRequestedAlgEncAndTheJwksKid() {
        for (alg in algs) for (enc in encs) {
            val jwe = jarm(alg, enc)
            val seg = jwe.split(".")
            assertEquals("$alg/$enc", 5, seg.size)
            // The encrypted-key segment is empty only for direct ECDH-ES.
            seg.forEachIndexed { i, v -> if (!(i == 1 && alg == "ECDH-ES")) assertTrue("$alg/$enc segment $i", v.isNotEmpty()) }
            assertEquals("$alg/$enc", alg == "ECDH-ES", seg[1].isEmpty())
            val header = JWEObject.parse(jwe).header
            assertEquals(alg, header.algorithm.name)
            assertEquals(enc, header.encryptionMethod.name)
            assertEquals("verifier-key-1", header.keyID)
            assertTrue(AuthorizationResponseEncryption.isConformant(jwe, alg, enc, "verifier-key-1"))
        }
    }

    @Test
    fun aJwkWithoutAKidYieldsAHeaderWithoutOne() {
        val noKid = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate()
        val jwe = jarm("ECDH-ES", "A128GCM", Json.parseToJsonElement(noKid.toPublicJWK().toJSONString()).jsonObject)
        assertNull(JWEObject.parse(jwe).header.keyID)
        assertTrue(AuthorizationResponseEncryption.isConformant(jwe, "ECDH-ES", "A128GCM", null))
        assertFalse(AuthorizationResponseEncryption.isConformant(jwe, "ECDH-ES", "A128GCM", "invented"))
    }

    @Test
    fun theConformanceCheckRefusesWhatTheEngineRefuses() {
        val good = jarm("ECDH-ES+A256KW", "A128GCM")
        fun ok(jwe: String, alg: String = "ECDH-ES+A256KW", enc: String = "A128GCM", kid: String? = "verifier-key-1") =
            AuthorizationResponseEncryption.isConformant(jwe, alg, enc, kid)
        assertTrue(ok(good))
        // header alg / enc / kid differ from the request's
        assertFalse(ok(good, alg = "ECDH-ES"))
        assertFalse(ok(good, enc = "A256GCM"))
        assertFalse(ok(good, kid = "another-kid"))
        assertFalse(ok(good, kid = null))
        // not five segments, or an empty one (the key segment is only allowed empty for direct ECDH-ES)
        val seg = good.split(".")
        assertFalse(ok(seg.take(4).joinToString(".")))
        assertFalse(ok((seg + "x").joinToString(".")))
        for (i in 0..4) assertFalse("empty segment $i", ok(seg.mapIndexed { j, v -> if (j == i) "" else v }.joinToString(".")))
        assertFalse(ok(""))
        assertFalse(ok(seg.mapIndexed { j, v -> if (j == 3) "$v!" else v }.joinToString(".")))
        // direct ECDH-ES may leave the key segment empty, and only that one
        val direct = jarm("ECDH-ES", "A128GCM")
        assertTrue(ok(direct, alg = "ECDH-ES"))
        // over 4 MiB
        assertFalse(ok(good + "A".repeat(AuthorizationResponseEncryption.MAX_RESPONSE_JWE_BYTES)))
    }

    @Test
    fun aResponseOverFourMebibytesIsNeverBuilt() {
        val huge = JsonPrimitive("x".repeat(AuthorizationResponseEncryption.MAX_RESPONSE_JWE_BYTES))
        assertThrows(IllegalArgumentException::class.java) { jarm("ECDH-ES", "A128GCM", vp = huge) }
    }

    @Test
    fun anErrorResponseCarriesTheErrorAndStateAndNoVpToken() {
        val jwe = AuthorizationResponseEncryption.encryptError(
            "access_denied", "x509_san_dns:verifier.example", "state-123", publicJwk(verifier), "ECDH-ES", "A128GCM", nowSeconds = 1_700_000_000,
        )
        val (header, claims) = decryptJarm(jwe)
        assertEquals("verifier-key-1", header.keyID)
        assertEquals("access_denied", claims["error"]!!.jsonPrimitive.content)
        assertEquals("state-123", claims["state"]!!.jsonPrimitive.content)
        assertEquals("x509_san_dns:verifier.example", claims["aud"]!!.jsonPrimitive.content)
        assertEquals(1_700_000_300L, claims["exp"]!!.jsonPrimitive.content.toLong())
        assertFalse(claims.containsKey("vp_token"))
        assertFalse(claims.containsKey("error_description"))
        assertTrue(AuthorizationResponseEncryption.isConformant(jwe, "ECDH-ES", "A128GCM", "verifier-key-1"))
        assertThrows(IllegalArgumentException::class.java) {
            AuthorizationResponseEncryption.encryptError("", "a", null, publicJwk(verifier), "ECDH-ES", "A128GCM")
        }
    }
}
