// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Round-trips [MdocCose.sign1Detached]/[MdocCose.verify1] against a real ECDSA P-256 key pair. */
class MdocCoseTest {

    /** JDK ECDSA `Signature.sign()` always returns ASN.1 DER; the COSE/mdoc wire format is raw r||s. */
    private fun derToRaw(der: ByteArray, componentLength: Int): ByteArray {
        // SEQUENCE(0x30, len) INTEGER(0x02, len, bytes) INTEGER(0x02, len, bytes) -
        // the outer SEQUENCE's own length can be long-form (P-521/ES512's
        // body is always >= 128 bytes), so this can't assume a fixed 2-byte
        // header the way an earlier version of this helper did.
        require(der[0] == 0x30.toByte()) { "expected ASN.1 SEQUENCE tag" }
        var offset = 1
        val firstLengthByte = der[offset].toInt() and 0xFF
        offset++
        if (firstLengthByte and 0x80 != 0) {
            val numLengthBytes = firstLengthByte and 0x7F
            offset += numLengthBytes
        }
        fun readInteger(): ByteArray {
            require(der[offset] == 0x02.toByte()) { "expected ASN.1 INTEGER tag" }
            offset++
            val len = der[offset].toInt() and 0xFF
            offset++
            val bytes = der.copyOfRange(offset, offset + len)
            offset += len
            return bytes
        }
        val rBytes = readInteger()
        val sBytes = readInteger()
        val r = BigInteger(1, rBytes)
        val s = BigInteger(1, sBytes)

        val out = ByteArray(componentLength * 2)
        val rFixed = r.toByteArray().let { if (it.size > componentLength) it.copyOfRange(it.size - componentLength, it.size) else it }
        val sFixed = s.toByteArray().let { if (it.size > componentLength) it.copyOfRange(it.size - componentLength, it.size) else it }
        System.arraycopy(rFixed, 0, out, componentLength - rFixed.size, rFixed.size)
        System.arraycopy(sFixed, 0, out, componentLength * 2 - sFixed.size, sFixed.size)
        return out
    }

    @Test
    fun `verify1 accepts a signature produced by sign1Detached`() = runTest {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val payload = "ReaderAuthentication test payload".toByteArray()

        val sign1 = MdocCose.sign1Detached("ES256", payload) { toBeSigned ->
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(keyPair.private)
            signer.update(toBeSigned)
            derToRaw(signer.sign(), 32)
        }

        assertTrue(MdocCose.verify1(sign1, payload, keyPair.public))
    }

    @Test
    fun `verify1 rejects a tampered payload`() = runTest {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val payload = "ReaderAuthentication test payload".toByteArray()

        val sign1 = MdocCose.sign1Detached("ES256", payload) { toBeSigned ->
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(keyPair.private)
            signer.update(toBeSigned)
            derToRaw(signer.sign(), 32)
        }

        val tamperedPayload = "different payload entirely".toByteArray()
        assertFalse(MdocCose.verify1(sign1, tamperedPayload, keyPair.public))
    }

    @Test
    fun `verify1 rejects a signature from the wrong key`() = runTest {
        val signingKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val otherKeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val payload = "ReaderAuthentication test payload".toByteArray()

        val sign1 = MdocCose.sign1Detached("ES256", payload) { toBeSigned ->
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(signingKeyPair.private)
            signer.update(toBeSigned)
            derToRaw(signer.sign(), 32)
        }

        assertFalse(MdocCose.verify1(sign1, payload, otherKeyPair.public))
    }

    /**
     * Regression test for a real Copilot-review finding: `rawEcdsaSignatureToDer`'s
     * DER length encoding previously used a single length byte
     * unconditionally, which breaks for ES512 (P-521) since its SEQUENCE
     * body (two ~67-byte INTEGER TLVs) is always >= 128 bytes and requires
     * ASN.1 DER long-form length encoding.
     */
    @Test
    fun `verify1 accepts an ES512 signature (P-521, exercises long-form DER length encoding)`() = runTest {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp521r1"))
        }.generateKeyPair()

        val payload = "ReaderAuthentication test payload".toByteArray()

        val sign1 = MdocCose.sign1Detached("ES512", payload) { toBeSigned ->
            val signer = Signature.getInstance("SHA512withECDSA")
            signer.initSign(keyPair.private)
            signer.update(toBeSigned)
            derToRaw(signer.sign(), 66)
        }

        assertTrue(MdocCose.verify1(sign1, payload, keyPair.public))
    }
}
