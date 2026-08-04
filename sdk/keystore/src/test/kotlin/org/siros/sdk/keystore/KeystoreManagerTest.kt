package org.siros.sdk.keystore

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
            override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<Long>, kid: String?) = ""
            override suspend fun signVpToken(credential: String, disclosedClaims: List<String>?, nonce: String, audience: String, kid: String?) = ""
            override suspend fun exportEncryptedContainer() = ByteArray(0)
            override fun listKeys() = emptyList<KeyInfo>()
            override suspend fun saveCredential(id: Long, json: String) {}
            override suspend fun getCredential(id: Long): String? = null
            override suspend fun getAllCredentials() = emptyMap<Long, String>()
            override suspend fun deleteCredential(id: Long) {}
            override suspend fun clearCredentials() {}
            override suspend fun savePresentationRecord(id: Long, json: String) {}
            override suspend fun getAllPresentationRecords() = emptyMap<Long, String>()
            override suspend fun clearPresentationRecords() {}
        }

        try {
            keystore.generateKeypairs(1)
            fail("Should throw UnsupportedOperationException")
        } catch (e: UnsupportedOperationException) {
            // expected
        }
    }
}
