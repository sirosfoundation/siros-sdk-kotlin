package org.siros.sdk.keystore

/**
 * Manages encrypted credential key storage.
 *
 * The keystore is unlocked using a PRF-derived key (from WebAuthn)
 * and contains private keys for credential signing operations.
 * The encrypted container is synchronized with the backend for
 * cross-device portability.
 *
 * This interface intentionally does NOT bind to platform-native key storage.
 * A future Signer abstraction layer will enable hardware-backed keys.
 */
interface KeystoreManager {
    /** Whether the keystore is currently unlocked and usable. */
    val isUnlocked: Boolean

    /** Unlock the keystore using PRF-derived key material. */
    suspend fun unlock(prfOutput: ByteArray, encryptedContainer: ByteArray)

    /** Lock the keystore, clearing key material from memory. */
    fun lock()

    /** Generate a new keypair and return the key ID. */
    suspend fun generateKey(algorithm: String = "ES256"): String

    /**
     * Sign a payload with the specified key.
     * @param keyId the key identifier
     * @param payload the data to sign
     * @param algorithm signing algorithm (e.g. "ES256")
     * @return the signature bytes
     */
    suspend fun sign(keyId: String, payload: ByteArray, algorithm: String = "ES256"): ByteArray

    /**
     * Generate a proof JWT for credential issuance (c_nonce binding).
     * @param audience the credential issuer URL
     * @param nonce the c_nonce value from the issuer
     * @return the signed proof JWT
     */
    suspend fun generateProof(audience: String, nonce: String): String

    /**
     * Sign a verifiable presentation for OID4VP.
     * @param nonce the verifier nonce
     * @param audience the verifier URL
     * @param credentialIds the credential identifiers to include
     * @return the signed VP JWT
     */
    suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<String>): String

    /** Export the encrypted container for backend sync. */
    suspend fun exportEncryptedContainer(): ByteArray

    /** List all key IDs in the keystore. */
    fun listKeys(): List<KeyInfo>
}

data class KeyInfo(
    val keyId: String,
    val algorithm: String,
    val createdAt: Long,
)
