package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JweKeystoreTest {

    private val fakePrfOutput = ByteArray(32) { it.toByte() }
    private val hkdfSalt = ByteArray(32) { (it + 0x10).toByte() }
    private val hkdfInfo = "SIROS Wallet PRF".toByteArray(Charsets.UTF_8)

    @Test
    fun unlockWithEmptyContainerCreatesFreshKeystore() = runTest {
        val keystore = JweKeystore()
        assertFalse(keystore.isUnlocked)

        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        assertTrue(keystore.isUnlocked)
        assertEquals(0, keystore.listKeys().size)
    }

    @Test
    fun generateKeyAndListKeys() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        val keyId = keystore.generateKey()
        assertNotNull(keyId)

        val keys = keystore.listKeys()
        assertEquals(1, keys.size)
        assertEquals(keyId, keys[0].keyId)
    }

    @Test
    fun exportAndReimportContainer() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        // Generate a key and export
        val keyId = keystore.generateKey()
        val exported = keystore.exportEncryptedContainer()
        assertTrue(exported.isNotEmpty())

        // Lock and re-unlock with the same PRF output
        keystore.lock()
        assertFalse(keystore.isUnlocked)

        keystore.unlock(fakePrfOutput, exported, hkdfSalt, hkdfInfo)
        assertTrue(keystore.isUnlocked)
        assertEquals(1, keystore.listKeys().size)
        assertEquals(keyId, keystore.listKeys()[0].keyId)
    }

    @Test
    fun lockClearsKeys() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()
        assertEquals(1, keystore.listKeys().size)

        keystore.lock()
        assertFalse(keystore.isUnlocked)
    }

    @Test
    fun signProducesOutput() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        val keyId = keystore.generateKey()

        val signed = keystore.sign(keyId, "test payload".toByteArray())
        assertTrue(signed.isNotEmpty())
    }

    @Test
    fun generateProofProducesJwt() = runTest {
        val keystore = JweKeystore()
        keystore.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.generateKey()

        val proof = keystore.generateProof("https://issuer.example.com", "test-nonce-123")
        assertTrue(proof.contains("."))  // JWT has dots
        assertEquals(3, proof.split(".").size)  // header.payload.signature
    }

    @Test
    fun differentPrfOutputProducesDifferentKeys() = runTest {
        val keystore1 = JweKeystore()
        keystore1.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore1.generateKey()
        val exported = keystore1.exportEncryptedContainer()

        // Trying to unlock with different PRF output should fail (wrong key)
        val differentPrf = ByteArray(32) { (it + 0x80).toByte() }
        val keystore2 = JweKeystore()
        try {
            keystore2.unlock(differentPrf, exported, hkdfSalt, hkdfInfo)
            // If we get here, decryption silently succeeded with wrong key (unlikely)
            // The JWE library should throw
            assert(false) { "Should have thrown on wrong key" }
        } catch (_: Exception) {
            // Expected: decryption fails with wrong key
        }
    }
}
