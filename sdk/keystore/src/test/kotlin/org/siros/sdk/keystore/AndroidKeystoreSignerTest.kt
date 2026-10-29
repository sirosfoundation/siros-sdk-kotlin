// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
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

        var generatedOn: String? = null
        var signedOn: String? = null
        /** Invoked synchronously right after the key is persisted, still inside generate() - simulates cancellation racing the dispatcher handoff back from the IO thread. */
        var afterGenerate: (() -> Unit)? = null

        override fun generate(alias: String, attestationChallenge: ByteArray?, strongBox: Boolean) {
            generatedOn = Thread.currentThread().name
            if (strongBox && !strongBoxAvailable) throw AndroidKeyStoreBackend.StrongBoxUnavailable()
            generated += Generated(alias, attestationChallenge?.copyOf(), strongBox)
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey
            afterGenerate?.invoke()
        }

        override fun certificateChain(alias: String): List<ByteArray> = List(chainLength) { i -> byteArrayOf(alias.length.toByte(), i.toByte()) }
        override fun publicKey(alias: String): ECPublicKey = keys.getValue(alias)
        override fun signDer(alias: String, data: ByteArray): ByteArray { signedOn = Thread.currentThread().name; return derSignature }
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

    /**
     * Review of #312: Android Keystore has already persisted the key by the time create() returns from the IO
     * dispatcher, so a cancellation landing exactly at the handoff back to the caller must not leak it - the caller
     * never receives the alias (CancellationException propagates instead), and from the wallet's point of view the
     * key simply does not exist, so it can never be deleted through the ordinary deleteKey path.
     */
    @Test
    fun aCancellationAtTheDispatcherHandoffDeletesTheAlreadyPersistedKeyInsteadOfLeakingIt() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        lateinit var job: Job
        b.afterGenerate = { job.cancel() } // the key is already persisted; cancel right as create() is about to return
        job = launch {
            runCatching { s.generateKey("ES256") }
        }
        job.join()
        assertTrue("the orphaned key was deleted, not left behind", b.deleted.isNotEmpty())
        assertTrue("no key survives in the backend", b.aliases().isEmpty())
    }

    /** Same race, but for the attested-key path (a separate call site in AndroidKeystoreSigner). */
    @Test
    fun aCancellationAtTheDispatcherHandoffDeletesTheAlreadyPersistedAttestedKeyInsteadOfLeakingIt() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        lateinit var job: Job
        b.afterGenerate = { job.cancel() }
        job = launch {
            runCatching { s.generateAttestedKey("ES256", ByteArray(32) { 1 }) }
        }
        job.join()
        assertTrue(b.deleted.isNotEmpty())
        assertTrue(b.aliases().isEmpty())
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
        // kid carries the key id so WscdKeystoreAdapter/SirosWallet.extractProofKeyId can recover which holder key an
        // embedded-JWK proof was made with (a multi-key mdoc batch would otherwise fall back to the wrong key).
        assertEquals(id, (jwk["kid"] as kotlinx.serialization.json.JsonPrimitive).content)
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

    @Test
    fun hardwareKeyGenerationAndSigningNeverRunOnTheCallersDispatcher() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val caller = Thread.currentThread().name
        val id = s.generateAttestedKey("ES256", ByteArray(32) { 1 })
        val attestedOn = b.generatedOn!!
        s.generateKey("ES256")
        val plainOn = b.generatedOn!!
        b.derSignature = der(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        s.sign(id, byteArrayOf(1))
        assertTrue("attested generation ran on $attestedOn, the caller is $caller", attestedOn.startsWith("DefaultDispatcher") && attestedOn != caller)
        assertTrue("plain generation ran on $plainOn", plainOn.startsWith("DefaultDispatcher"))
        assertTrue("signing ran on ${b.signedOn}", b.signedOn!!.startsWith("DefaultDispatcher"))
    }
}
