// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AndroidKeystoreSignerTest {
    private class Generated(val alias: String, val challenge: ByteArray?, val strongBox: Boolean)

    private class FakeBackend(var strongBoxAvailable: Boolean = true, var chainLength: Int = 3) : AndroidKeyStoreBackend {
        val generated = mutableListOf<Generated>()
        val deleted = mutableListOf<String>()
        val keys = linkedMapOf<String, ECPublicKey>()
        var derSignature: ByteArray = byteArrayOf()

        override fun generate(alias: String, attestationChallenge: ByteArray?, strongBox: Boolean) {
            if (strongBox && !strongBoxAvailable) throw AndroidKeyStoreBackend.StrongBoxUnavailable()
            generated += Generated(alias, attestationChallenge?.copyOf(), strongBox)
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey
        }

        override fun certificateChain(alias: String): List<ByteArray> = List(chainLength) { i -> byteArrayOf(alias.length.toByte(), i.toByte()) }
        override fun publicKey(alias: String): ECPublicKey = keys.getValue(alias)
        override fun signDer(alias: String, data: ByteArray): ByteArray = derSignature
        override fun aliases(): List<String> = keys.keys.toList()
        override fun delete(alias: String) { deleted += alias; keys.remove(alias) }
    }

    private fun signer(b: FakeBackend): AndroidKeystoreSigner {
        var n = 0
        return AndroidKeystoreSigner(b, newAlias = { AndroidKeystoreSigner.ALIAS_PREFIX + (++n) })
    }

    @Test
    fun anAttestedKeyIsAskedForStrongBoxFirstWithTheChallenge() = runTest {
        val b = FakeBackend()
        val challenge = ByteArray(32) { it.toByte() }
        val id = signer(b).generateAttestedKey("ES256", challenge)
        assertEquals(1, b.generated.size)
        assertTrue(b.generated.single().strongBox)
        assertArrayEquals(challenge, b.generated.single().challenge)
        assertEquals(id, b.generated.single().alias)
    }

    @Test
    fun withoutStrongBoxItFallsBackToTheTeeOnANewAlias_withTheSameChallenge() = runTest {
        val b = FakeBackend(strongBoxAvailable = false)
        val challenge = ByteArray(32) { 7 }
        val s = signer(b)
        val id = s.generateAttestedKey("ES256", challenge)
        assertEquals(1, b.generated.size)
        assertFalse(b.generated.single().strongBox)
        assertArrayEquals(challenge, b.generated.single().challenge)
        assertEquals("the first alias was dropped and the TEE key lives under a new one", listOf(AndroidKeystoreSigner.ALIAS_PREFIX + "1"), b.deleted)
        assertEquals(AndroidKeystoreSigner.ALIAS_PREFIX + "2", id)
        assertEquals(listOf("trusted_execution"), s.securityProperties(id).keyStorage)
    }

    @Test
    fun aStrongBoxKeyIsReportedAsHardware() = runTest {
        val s = signer(FakeBackend())
        val id = s.generateAttestedKey("ES256", ByteArray(32) { 1 })
        assertEquals(listOf("hardware"), s.securityProperties(id).keyStorage)
    }

    @Test
    fun theChainIsDerLeafFirstInAndroidKeyFormat_andAbsentForALoneCertificate() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val id = s.generateAttestedKey("ES256", ByteArray(32))
        val chain = s.attestationChain(id)!!
        assertEquals(AttestationChain.FORMAT_ANDROID_KEY, chain.format)
        assertEquals(listOf(0, 1, 2), chain.certificates.map { it[1].toInt() }) // order as the keystore returned it: leaf first
        assertEquals(0, chain.clientDataHash.size)
        b.chainLength = 1
        assertNull(s.attestationChain(id))
    }

    @Test
    fun onlyEs256AndANonEmptyChallengeAreAccepted() = runTest {
        val s = signer(FakeBackend())
        for (call in listOf<suspend () -> Unit>(
            { s.generateKey("EdDSA") },
            { s.generateAttestedKey("RS256", ByteArray(32)) },
            { s.generateAttestedKey("ES256", ByteArray(0)) },
        )) {
            try {
                call()
                fail("accepted")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun aPlainKeyHasNoChallenge() = runTest {
        val b = FakeBackend()
        signer(b).generateKey("ES256")
        assertNull(b.generated.single().challenge)
    }

    private fun der(r: ByteArray, s: ByteArray): ByteArray {
        fun int(v: ByteArray) = byteArrayOf(0x02, v.size.toByte()) + v
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    @Test
    fun aDerSignatureBecomesTheFixedWidthJwsForm() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val id = s.generateKey("ES256")
        // r has a leading zero (high bit set), s is short: both must come out 32 bytes wide.
        val r = byteArrayOf(0) + ByteArray(32) { 0xF0.toByte() }
        val sShort = byteArrayOf(1, 2, 3)
        b.derSignature = der(r, sShort)
        val raw = s.sign(id, byteArrayOf(1))
        assertEquals(64, raw.size)
        assertArrayEquals(ByteArray(32) { 0xF0.toByte() }, raw.copyOfRange(0, 32))
        assertArrayEquals(ByteArray(29) + byteArrayOf(1, 2, 3), raw.copyOfRange(32, 64))
    }

    @Test
    fun theExportedPublicKeyIsAP256Jwk() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val id = s.generateKey("ES256")
        val jwk = kotlinx.serialization.json.Json.parseToJsonElement(String(s.exportPublicKey(id))) as kotlinx.serialization.json.JsonObject
        assertEquals("P-256", (jwk["crv"] as kotlinx.serialization.json.JsonPrimitive).content)
        val x = Base64.getUrlDecoder().decode((jwk["x"] as kotlinx.serialization.json.JsonPrimitive).content)
        val y = Base64.getUrlDecoder().decode((jwk["y"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals(32, x.size)
        assertEquals(32, y.size)
        val pub = b.publicKey(id)
        assertEquals(java.math.BigInteger(1, x), pub.w.affineX)
        assertEquals(java.math.BigInteger(1, y), pub.w.affineY)
    }

    @Test
    fun listAndDeleteOnlyTouchTheSignersOwnKeys() = runTest {
        val b = FakeBackend()
        b.keys["foreign"] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey
        val s = signer(b)
        val id = s.generateKey("ES256")
        assertEquals(listOf(id), s.listKeys().map { it.keyId })
        s.deleteKey(id)
        assertTrue(s.listKeys().isEmpty())
    }

    @Test
    fun theSignerAnnouncesTheCapability_andMigrationNeedsReEnrollment() = runTest {
        val s = signer(FakeBackend())
        assertTrue(s.supportsAttestedKeyGeneration)
        assertTrue(s.migrateKey("k", "other") is MigrationResult.ReEnrollmentRequired)
    }
}
