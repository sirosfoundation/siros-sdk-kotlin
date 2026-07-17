package org.sirosfoundation.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.fail
import org.junit.Test

class KeystoreManagerTest {

    @Test
    fun generateKeypairsDefaultThrowsUnsupported() = runTest {
        val keystore = object : KeystoreManager {
            override val isUnlocked = true
            override suspend fun unlock(prfOutput: ByteArray, encryptedContainer: ByteArray, hkdfSalt: ByteArray, hkdfInfo: ByteArray) {}
            override fun lock() {}
            override suspend fun generateKey(algorithm: String) = "key-1"
            override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String) = ByteArray(0)
            override suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean) = ""
            override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<String>) = ""
            override suspend fun signVpToken(credential: String, disclosedClaims: List<String>?, nonce: String, audience: String) = ""
            override suspend fun exportEncryptedContainer() = ByteArray(0)
            override fun listKeys() = emptyList<KeyInfo>()
            override suspend fun saveCredential(id: String, json: String) {}
            override suspend fun getCredential(id: String): String? = null
            override suspend fun getAllCredentials() = emptyMap<String, String>()
            override suspend fun deleteCredential(id: String) {}
            override suspend fun clearCredentials() {}
        }

        try {
            keystore.generateKeypairs(1)
            fail("Should throw UnsupportedOperationException")
        } catch (e: UnsupportedOperationException) {
            // expected
        }
    }
}
