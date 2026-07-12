package org.sirosfoundation.sdk.keystore

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

    /**
     * Unlock the keystore using PRF-derived key material.
     *
     * @param prfOutput   raw PRF output from the WebAuthn authenticator.
     * @param encryptedContainer the JWE container (may be empty for first-time setup).
     * @param hkdfSalt    HKDF extraction salt (32 bytes).
     * @param hkdfInfo    HKDF expansion info (e.g. "eDiplomas PRF").
     */
    suspend fun unlock(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray = ByteArray(32),
        hkdfInfo: ByteArray = "eDiplomas PRF".toByteArray(Charsets.UTF_8),
    )

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
    suspend fun generateProof(audience: String, nonce: String, freshKey: Boolean = false): String

    /**
     * Sign a verifiable presentation for OID4VP.
     * @param nonce the verifier nonce
     * @param audience the verifier URL
     * @param credentialIds the credential identifiers to include
     * @return the signed VP JWT
     */
    suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<String>): String

    /**
     * Build a complete SD-JWT VP token with Key Binding JWT.
     *
     * Takes the raw SD-JWT credential, filters disclosures to only those
     * matching [disclosedClaims], computes the `sd_hash`, and signs a
     * KB-JWT with `typ: "kb+jwt"` and the holder's public key in `jwk`.
     *
     * The returned string is the full VP token:
     * `IssuerJWT~disclosure1~...~disclosureN~KB-JWT`
     *
     * @param credential the raw SD-JWT credential string.
     * @param disclosedClaims claim names to selectively disclose (null = all).
     * @param nonce the verifier-provided nonce.
     * @param audience the verifier's client_id.
     * @return the assembled VP token string.
     */
    suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
    ): String

    /**
     * Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation.
     *
     * @param credentialBytes Raw CBOR bytes of the IssuerSigned structure.
     * @param disclosedClaims Claim names to disclose (null = all).
     * @param nonce Verifier-provided nonce.
     * @param audience Verifier client_id.
     * @param responseUri Verifier response endpoint URI.
     * @param verifierJwkThumbprint Optional JWK thumbprint for session transcript.
     * @return Base64url-encoded DeviceResponse CBOR bytes.
     */
    suspend fun signMdocPresentation(
        credentialBytes: ByteArray,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
    ): ByteArray {
        throw UnsupportedOperationException("mDoc presentation not supported by this keystore")
    }

    /** Export the encrypted container for backend sync. */
    suspend fun exportEncryptedContainer(): ByteArray

    /** List all key IDs in the keystore. */
    fun listKeys(): List<KeyInfo>

    // ── Credential storage (PRF-encrypted alongside keys) ───────────

    /** Store a credential's raw JSON inside the encrypted container. */
    suspend fun saveCredential(id: String, json: String)

    /** Get a stored credential's raw JSON by ID. Returns null if not found. */
    suspend fun getCredential(id: String): String?

    /** Get all stored credential JSON blobs (id → json). */
    suspend fun getAllCredentials(): Map<String, String>

    /** Remove a credential by ID. */
    suspend fun deleteCredential(id: String)

    /** Remove all stored credentials. */
    suspend fun clearCredentials()

    /**
     * Generate [count] keypairs and return their public JWKs.
     * Used for key attestation requests.
     *
     * Default implementation throws [UnsupportedOperationException] so
     * existing implementations continue to compile without attestation support.
     */
    suspend fun generateKeypairs(count: Int): List<KeypairInfo> {
        throw UnsupportedOperationException("generateKeypairs not supported by this keystore")
    }

    /**
     * Get the security properties for this keystore's signing keys.
     * Used to populate KA JWT claims (CS-04 §7.1.3, Annex C §C.3.1).
     *
     * Default returns null (security properties not available).
     */
    suspend fun securityProperties(): SignerSecurityProperties? = null
}

data class KeyInfo(
    val keyId: String,
    val algorithm: String,
    val createdAt: Long,
)

data class KeypairInfo(
    val keyId: String,
    val publicKeyJWK: kotlinx.serialization.json.JsonObject,
)
