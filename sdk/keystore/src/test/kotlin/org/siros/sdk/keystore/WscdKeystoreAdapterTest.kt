package org.siros.sdk.keystore

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
            certification = org.siros.sdk.credentials.CertificationInfo.Certified(
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

    @Test(expected = org.siros.sdk.credentials.KeystoreException::class)
    fun exportEncryptedContainerThrowsWhenLocked() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.exportEncryptedContainer()
    }

    @Test
    fun exportAndRestoreCredentialsRoundTrip() = runTest {
        val prfOutput = ByteArray(32) { it.toByte() }
        val hkdfSalt = ByteArray(32) { (it * 2).toByte() }
        val hkdfInfo = "test-info".toByteArray()

        val adapter1 = WscdKeystoreAdapter(createMockSigner())
        adapter1.unlock(prfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        // Realistic shape: EncryptedCredentialStore always saves the full
        // StoredCredential JSON (id/format/raw/kid/...) - the underlying
        // JweKeystore container only round-trips the privatedata-spec's
        // normative fields (format/kid/raw as "data"), not arbitrary JSON.
        adapter1.saveCredential("cred-1", """{"id":"cred-1","format":"vc+sd-jwt","raw":"header.payload.sig","kid":"key-1"}""")
        val exported = adapter1.exportEncryptedContainer()
        assertTrue(exported.isNotEmpty())

        // A fresh adapter, unlocked with the SAME PRF material and the
        // exported container, should recover the credential - this is what
        // makes credentials survive logout+login for WSCD-backed keystores
        // (previously exportEncryptedContainer() just threw, so nothing was
        // ever persisted at all), AND (per privatedata-spec) uses the exact
        // same container format wallet-frontend/JweKeystore-backed native
        // clients use, so the same passkey unlocks the same credentials
        // across any client, not just this WSCD-backed one.
        val adapter2 = WscdKeystoreAdapter(createMockSigner())
        adapter2.unlock(prfOutput, exported, hkdfSalt, hkdfInfo)
        val restored = adapter2.getCredential("cred-1")
        assertNotNull(restored)
        assertTrue(restored!!.contains("\"format\":\"vc+sd-jwt\""))
        assertTrue(restored.contains("header.payload.sig"))
    }

    @Test(expected = Exception::class)
    fun unlockWithWrongPrfOutputThrows() = runTest {
        val hkdfSalt = ByteArray(32) { (it * 2).toByte() }
        val hkdfInfo = "test-info".toByteArray()

        val adapter1 = WscdKeystoreAdapter(createMockSigner())
        adapter1.unlock(ByteArray(32) { it.toByte() }, ByteArray(0), hkdfSalt, hkdfInfo)
        adapter1.saveCredential("cred-1", """{"id":"cred-1","format":"vc+sd-jwt","raw":"x"}""")
        val exported = adapter1.exportEncryptedContainer()

        // A wrong PRF output must fail loudly (not silently start empty) -
        // matches JweKeystore's own existing behavior for a wrong key.
        val adapter2 = WscdKeystoreAdapter(createMockSigner())
        adapter2.unlock(ByteArray(32) { (it + 1).toByte() }, exported, hkdfSalt, hkdfInfo)
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
