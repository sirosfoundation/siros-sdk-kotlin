package org.sirosfoundation.sdk.keystore

/**
 * Minimal signing interface for raw key operations.
 *
 * Represents the cryptographic backend (WSCD) layer that performs
 * key generation, signing, and attestation. Implementations may use
 * software keys, hardware tokens (FIDO2/CTAP2), or remote HSMs (R2PS/PKCS#11).
 */
interface Signer {
    /**
     * Generate a new keypair.
     * @param algorithm Algorithm identifier (e.g. "ES256", "EdDSA").
     * @return The key ID of the generated key.
     */
    suspend fun generateKey(algorithm: String): String

    /**
     * Sign raw data with the specified key.
     * @param keyId ID of the key to use.
     * @param data Raw bytes to sign.
     * @return The signature bytes.
     */
    suspend fun sign(keyId: String, data: ByteArray): ByteArray

    /** List all keys managed by this signer. */
    suspend fun listKeys(): List<SignerKeyInfo>

    /** Delete a key by ID. */
    suspend fun deleteKey(keyId: String)

    /**
     * Return the attestation certificate chain for a key, if available.
     *
     * For hardware-backed keys (FIDO2, CTAP2), this returns the
     * attestation statement certificate chain proving key provenance.
     * For software keys, returns null.
     */
    suspend fun attestationChain(keyId: String): List<ByteArray>?

    /**
     * Export the public key in JWK format (JSON-encoded bytes).
     */
    suspend fun exportPublicKey(keyId: String): ByteArray

    /**
     * Migrate a key from one WSCD plugin to another.
     *
     * @param keyId the key to migrate.
     * @param targetPlugin the target plugin identifier.
     * @return the migration result.
     */
    suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult

    /**
     * Return the security properties for a key.
     *
     * Reports key storage type, certification level, user authentication
     * methods, and AMR values. The [amr] field reflects the authentication
     * methods used in the most recent [sign] operation.
     */
    suspend fun securityProperties(keyId: String): SignerSecurityProperties
}

/** Result of a key migration operation. */
sealed class MigrationResult {
    /** Key migrated successfully; contains the new key ID. */
    data class Migrated(val newKeyId: String) : MigrationResult()
    /** Migration requires full re-enrollment with the issuer. */
    data class ReEnrollmentRequired(val oldKeyId: String) : MigrationResult()
}

data class SignerKeyInfo(
    val keyId: String,
    val algorithm: String,
)

/**
 * Certification information for the WSCD (CS-04 §7.1.3, Annex C §C.3.1).
 * Either the string "none" for uncertified devices, or a structured object
 * with scheme and assurance level.
 */
sealed class CertificationInfo {
    /** No certification. */
    data object None : CertificationInfo()

    /** Certified under a specific scheme. */
    data class Certified(
        val scheme: String,
        val assuranceLevel: String,
    ) : CertificationInfo()

    /** Serialize to the JSON-compatible form expected by the backend. */
    fun toJsonValue(): Any = when (this) {
        is None -> "none"
        is Certified -> mapOf("scheme" to scheme, "assurance_level" to assuranceLevel)
    }
}

/** Security properties reported by a [Signer] for a given key. */
data class SignerSecurityProperties(
    /** Key storage security levels — ISO 18045 AVA_VAN scale values. */
    val keyStorage: List<String>,
    /** User authentication methods supported. */
    val userAuthentication: List<String> = emptyList(),
    /** Certification status of the key storage (CS-04 §7.1.3, Annex C §C.3.1). */
    val certification: CertificationInfo = CertificationInfo.None,
    /** Authentication Method Reference values from the last sign operation. */
    val amr: List<String> = emptyList(),
)
