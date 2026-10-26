// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.KeystoreException

/**
 * Feeds the DER parser random and mutated inputs (fixed seed, so a failure reproduces): every
 * input must be refused with `invalid_signature` or accepted as a canonical signature. Nothing
 * else (no other exception, no hang, no non-canonical acceptance) is allowed.
 */
class EcdsaSignaturesFuzzTest {

    private val random = Random(20261026)
    private val halfOrder = EcdsaSignatures.P256_ORDER.shiftRight(1)

    /** Accepted only if it is exactly the strict DER of an (r, s) in range, and maps to 64 canonical bytes. */
    private fun check(input: ByteArray) {
        val raw = try {
            EcdsaSignatures.derToRawLowS(input)
        } catch (e: KeystoreException) {
            assertEquals("invalid_signature", e.errorCode)
            return
        } catch (e: Throwable) {
            fail("${e.javaClass.simpleName} for ${hex(input)}")
            return
        }
        assertEquals(64, raw.size)
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        assertTrue(r.signum() > 0 && r < EcdsaSignatures.P256_ORDER)
        assertTrue(s.signum() > 0 && s <= halfOrder)
        // The input must be the strict DER of (r, s) or of (r, n - s): nothing looser was accepted.
        val lowDer = EcdsaSignatures.rawToDer(raw)
        val highDer = EcdsaSignatures.rawToDer(raw.copyOfRange(0, 32) + fixed(EcdsaSignatures.P256_ORDER - s))
        assertTrue("accepted a non-canonical encoding ${hex(input)}", input.contentEquals(lowDer) || input.contentEquals(highDer))
        assertArrayEquals(raw, EcdsaSignatures.derToRawLowS(lowDer))
    }

    @Test
    fun randomBytes_areRefusedCleanly() {
        repeat(50_000) {
            check(random.nextBytes(random.nextInt(0, 80)))
        }
    }

    @Test
    fun randomBytesShapedLikeASignature_areRefusedOrCanonical() {
        repeat(50_000) {
            val rLen = random.nextInt(0, 35)
            val sLen = random.nextInt(0, 35)
            val body = byteArrayOf(0x02, rLen.toByte()) + random.nextBytes(rLen) + byteArrayOf(0x02, sLen.toByte()) + random.nextBytes(sLen)
            check(byteArrayOf(0x30, body.size.toByte()) + body)
        }
    }

    @Test
    fun mutationsOfRealSignatures_areRefusedOrCanonical() {
        val pair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        repeat(500) { i ->
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update("message $i".toByteArray())
                sign()
            }
            check(der) // the real one is accepted
            repeat(100) { check(mutate(der)) }
        }
    }

    private fun mutate(der: ByteArray): ByteArray {
        val b = der.copyOf()
        return when (random.nextInt(6)) {
            0 -> b.also { val i = random.nextInt(b.size); it[i] = (it[i].toInt() xor (1 shl random.nextInt(8))).toByte() } // flip a bit
            1 -> b.copyOf(random.nextInt(b.size)) // truncate
            2 -> b + random.nextBytes(random.nextInt(1, 4)) // extend
            3 -> b.also { val i = listOf(1, 3).random(random); it[i] = random.nextInt(256).toByte() } // a length byte
            4 -> b.also { it[random.nextInt(b.size)] = random.nextInt(256).toByte() } // any byte
            else -> byteArrayOf(b[0], b[1], 0x02, 0x01, 0x00) + b.copyOfRange(2, b.size) // an extra INTEGER
        }
    }

    private fun fixed(v: BigInteger): ByteArray {
        val bytes = v.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
            else -> ByteArray(32 - bytes.size) + bytes
        }
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}
