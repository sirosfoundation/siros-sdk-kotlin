package org.sirosfoundation.sdk.keystore

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class WscdKeystoreAdapterTest {

    private fun createMockSigner(): Signer = mockk<Signer>(relaxed = true).also {
        coEvery { it.generateKey(any()) } returns "test-key-1"
        coEvery { it.sign(any(), any()) } returns ByteArray(64) { it.toByte() }
        coEvery { it.listKeys() } returns listOf(
            SignerKeyInfo("test-key-1", "ES256")
        )
        coEvery { it.exportPublicKey(any()) } returns """{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}""".toByteArray()
        coEvery { it.deleteKey(any()) } returns Unit
        coEvery { it.attestationChain(any()) } returns null
        coEvery { it.securityProperties(any()) } returns SignerSecurityProperties(
            keyStorage = listOf("hardware"),
            userAuthentication = listOf("pin"),
            certification = CertificationInfo.Certified(
                scheme = "EUCC",
                assuranceLevel = "substantial",
            ),
        )
    }

    @Test
    fun initiallyLocked() {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        assertFalse(adapter.isUnlocked)
    }

    @Test
    fun unlockSetsState() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        assertTrue(adapter.isUnlocked)
    }

    @Test
    fun lockClearsState() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        assertTrue(adapter.isUnlocked)
        adapter.lock()
        assertFalse(adapter.isUnlocked)
    }

    @Test
    fun lockClearsCredentials() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        // Store a credential
        adapter.saveCredential("cred-1", """{"type":"VerifiableCredential"}""")
        assertNotNull(adapter.getCredential("cred-1"))

        // Lock should clear
        adapter.lock()

        // After re-unlock, credential should be gone
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        assertEquals(null, adapter.getCredential("cred-1"))
    }

    @Test
    fun generateKeyDelegatesToSigner() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val keyId = adapter.generateKey("ES256")
        assertEquals("test-key-1", keyId)
        coVerify { signer.generateKey("ES256") }
    }

    @Test
    fun signDelegatesToSigner() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val sig = adapter.sign("test-key-1", "hello".toByteArray(), "ES256")
        assertEquals(64, sig.size)
        coVerify { signer.sign("test-key-1", "hello".toByteArray()) }
    }

    @Test(expected = IllegalStateException::class)
    fun signThrowsWhenLocked() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.sign("key", "data".toByteArray(), "ES256")
    }

    @Test(expected = IllegalStateException::class)
    fun generateKeyThrowsWhenLocked() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.generateKey()
    }

    @Test
    fun listKeysDelegatesToSigner() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)

        val keys = adapter.listKeys()
        assertEquals(1, keys.size)
        assertEquals("test-key-1", keys[0].keyId)
    }

    @Test(expected = UnsupportedOperationException::class)
    fun exportEncryptedContainerThrows() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.exportEncryptedContainer()
    }

    @Test
    fun credentialCRUD() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        // Save
        adapter.saveCredential("id-1", """{"type":"VC"}""")
        adapter.saveCredential("id-2", """{"type":"VC2"}""")

        // Get
        assertEquals("""{"type":"VC"}""", adapter.getCredential("id-1"))
        assertEquals(null, adapter.getCredential("nonexistent"))

        // GetAll
        val all = adapter.getAllCredentials()
        assertEquals(2, all.size)

        // Delete
        adapter.deleteCredential("id-1")
        assertEquals(null, adapter.getCredential("id-1"))
        assertEquals(1, adapter.getAllCredentials().size)

        // Clear
        adapter.clearCredentials()
        assertEquals(0, adapter.getAllCredentials().size)
    }

    @Test
    fun attestationChainReturnsNull() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        adapter.generateKey()

        val chain = adapter.attestationChain("test-key-1")
        // MockK returns null for attestationChain
        assertEquals(null, chain)
    }

    @Test
    fun generateKeypairs() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val keypairs = adapter.generateKeypairs(2)
        assertEquals(2, keypairs.size)
        coVerify(exactly = 2) { signer.generateKey(any()) }
    }
}
