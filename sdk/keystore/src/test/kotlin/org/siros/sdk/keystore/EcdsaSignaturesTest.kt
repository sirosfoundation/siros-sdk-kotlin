// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.KeystoreException

class EcdsaSignaturesTest {

    private val halfOrder = EcdsaSignatures.P256_ORDER.shiftRight(1)

    private fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun derSign(pair: KeyPair, data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(pair.private)
        update(data)
        sign()
    }

    private fun verifies(pair: KeyPair, data: ByteArray, der: ByteArray): Boolean = Signature.getInstance("SHA256withECDSA").run {
        initVerify(pair.public)
        update(data)
        verify(der)
    }

    private fun s(raw: ByteArray) = BigInteger(1, raw.copyOfRange(32, 64))

    @Test
    fun derToRawLowS_givesA64ByteSignatureThatStillVerifies_andIsAlwaysLowS() {
        val pair = p256()
        repeat(64) { i ->
            val data = "message $i".toByteArray()
            val raw = EcdsaSignatures.derToRawLowS(derSign(pair, data))
            assertEquals(64, raw.size)
            assertTrue("s must be in the lower half", s(raw) <= halfOrder)
            assertTrue(verifies(pair, data, EcdsaSignatures.rawToDer(raw)))
        }
    }

    @Test
    fun derToRawLowS_flipsAHighS() {
        val r = BigInteger.valueOf(7)
        val highS = EcdsaSignatures.P256_ORDER - BigInteger.valueOf(5)
        val raw = EcdsaSignatures.derToRawLowS(der(r, highS))
        assertEquals(r, BigInteger(1, raw.copyOfRange(0, 32)))
        assertEquals(BigInteger.valueOf(5), s(raw))
    }

    @Test
    fun derToRawLowS_padsShortScalarsTo32Bytes() {
        val raw = EcdsaSignatures.derToRawLowS(der(BigInteger.ONE, BigInteger.TWO))
        val expected = ByteArray(64).also { it[31] = 1; it[63] = 2 }
        assertArrayEquals(expected, raw)
    }

    @Test
    fun rawToDer_roundTripsThroughDerToRawLowS() {
        val raw = ByteArray(64).also { it[0] = 0x80.toByte(); it[31] = 3; it[63] = 9 } // r needs a 0x00 pad in DER
        assertArrayEquals(raw, EcdsaSignatures.derToRawLowS(EcdsaSignatures.rawToDer(raw)))
    }

    @Test
    fun derToRawLowS_refusesMalformedSignatures() {
        val good = der(BigInteger.ONE, BigInteger.TWO)
        val cases = listOf(
            ByteArray(0),
            good.copyOf(good.size - 1), // truncated
            good + byteArrayOf(0), // trailing byte
            byteArrayOf(0x31) + good.copyOfRange(1, good.size), // not a SEQUENCE
            der(BigInteger.ZERO, BigInteger.ONE), // r = 0
            der(BigInteger.ONE, EcdsaSignatures.P256_ORDER), // s = n
            byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x81.toByte(), 0x02, 0x01, 0x01), // negative r
        )
        for (bytes in cases) {
            try {
                EcdsaSignatures.derToRawLowS(bytes)
                fail("accepted ${bytes.joinToString("") { "%02x".format(it) }}")
            } catch (e: KeystoreException) {
                assertEquals("invalid_signature", e.errorCode)
            }
        }
    }

    @Test
    fun publicJwk_hasTheP256MembersWith32ByteCoordinates() {
        val key = p256().public as ECPublicKey
        val jwk = Json.parseToJsonElement(EcdsaSignatures.publicJwk(key)).jsonObject
        assertEquals(setOf("kty", "crv", "x", "y"), jwk.keys)
        assertEquals("EC", jwk["kty"]!!.jsonPrimitive.content)
        assertEquals("P-256", jwk["crv"]!!.jsonPrimitive.content)
        val x = Base64.getUrlDecoder().decode(jwk["x"]!!.jsonPrimitive.content)
        val y = Base64.getUrlDecoder().decode(jwk["y"]!!.jsonPrimitive.content)
        assertEquals(32, x.size)
        assertEquals(32, y.size)
        assertEquals(key.w.affineX, BigInteger(1, x))
        assertEquals(key.w.affineY, BigInteger(1, y))
    }

    @Test
    fun publicJwk_includesKidWhenGiven() {
        val key = p256().public as ECPublicKey
        val jwk = Json.parseToJsonElement(EcdsaSignatures.publicJwk(key, kid = "the-key-id")).jsonObject
        assertEquals(setOf("kty", "crv", "x", "y", "kid"), jwk.keys)
        assertEquals("the-key-id", jwk["kid"]!!.jsonPrimitive.content)
    }

    @Test
    fun securityLevels_mapToTheKeyStorageNamesUniFFISignerUses() {
        assertEquals(AndroidKeystoreSigner.SecurityLevel.STRONGBOX, AndroidKeystoreSigner.levelOf(2))
        assertEquals(AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT, AndroidKeystoreSigner.levelOf(1))
        assertEquals(AndroidKeystoreSigner.SecurityLevel.SOFTWARE, AndroidKeystoreSigner.levelOf(0))
        assertEquals(AndroidKeystoreSigner.SecurityLevel.UNKNOWN, AndroidKeystoreSigner.levelOf(-2))
        assertEquals("hardware", AndroidKeystoreSigner.keyStorageName(AndroidKeystoreSigner.SecurityLevel.STRONGBOX))
        assertEquals("trusted_execution", AndroidKeystoreSigner.keyStorageName(AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT))
        assertEquals("software", AndroidKeystoreSigner.keyStorageName(AndroidKeystoreSigner.SecurityLevel.SOFTWARE))
        assertEquals("software", AndroidKeystoreSigner.keyStorageName(AndroidKeystoreSigner.SecurityLevel.UNKNOWN))
    }

    private fun der(r: BigInteger, s: BigInteger): ByteArray {
        fun int(v: BigInteger): ByteArray {
            val b = v.toByteArray()
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
