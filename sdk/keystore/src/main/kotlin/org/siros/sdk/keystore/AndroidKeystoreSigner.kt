// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.siros.sdk.credentials.COSE_ALG_ES256
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber

/**
 * A [Signer] over the Android Keystore: P-256 (ES256) keys made in StrongBox, the phone's separate
 * security chip (a Pixel's Titan M2), when the phone has one, otherwise in the TEE. The private key
 * never leaves that hardware; [sign] returns the raw `r || s` that JWS and COSE carry, with `s` in
 * low form.
 *
 * The keys are device-bound: nothing is exported ([exportPrivateKeypairs] stays empty), a key cannot
 * move to another plugin ([migrateKey] answers re-enrollment), and uninstalling the app deletes
 * them. No user authentication is bound to the keys: a host that needs it gates [sign] itself.
 *
 * Use it wherever a [Signer] goes (for example behind [WscdKeystoreAdapter]), or directly in the
 * low-level API: [zkWitnessSigner] is the device signature a ZK presentation binds
 * ([CircuitZkPresenter.present]).
 *
 * Not in this class (yet): Android Key Attestation ([attestationChain] returns null) and an entry
 * in [WscdPluginCapabilities] (it is a signer, not a siros-wscd-manager plugin).
 *
 * @param aliasPrefix Prefix of this signer's Android Keystore aliases; a key's id (a UUID) is the
 *   alias without it. Two signers with different prefixes never see each other's keys, also when
 *   one prefix extends the other.
 * @param preferStrongBox Try StrongBox first (default). `false` makes TEE keys only.
 */
class AndroidKeystoreSigner @JvmOverloads constructor(
    private val aliasPrefix: String = DEFAULT_ALIAS_PREFIX,
    private val preferStrongBox: Boolean = true,
) : Signer {

    /** Where a key is held, as the Android Keystore reports it. */
    enum class SecurityLevel {
        /** StrongBox: a separate security chip. */
        STRONGBOX,

        /** The TEE (or, before Android 12, "secure hardware" without telling StrongBox apart). */
        TRUSTED_ENVIRONMENT,

        /** A software key (an emulator, a phone without hardware-backed keys). */
        SOFTWARE,

        /** The Keystore did not say. */
        UNKNOWN,
    }

    init {
        require(aliasPrefix.isNotEmpty()) { "aliasPrefix must not be empty" }
    }

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } }

    private fun alias(keyId: String) = aliasPrefix + keyId

    /**
     * Makes a P-256 signing key: in StrongBox when [preferStrongBox] and the phone has it, else in
     * the TEE (a phone without StrongBox, or StrongBox refusing the key).
     *
     * @param algorithm `ES256` only.
     * @throws KeystoreException for another algorithm (`unsupported_algorithm`) or when the Keystore
     *   cannot make the key.
     */
    override suspend fun generateKey(algorithm: String): String = withContext(Dispatchers.IO) {
        if (!algorithm.equals(ES256, ignoreCase = true)) {
            throw KeystoreException(
                "The Android Keystore signer makes ES256 keys only, not $algorithm",
                errorCode = "unsupported_algorithm",
            )
        }
        val keyId = UUID.randomUUID().toString()
        val alias = alias(keyId)
        synchronized(keyStore) {
            try {
                if (preferStrongBox) {
                    try {
                        generate(alias, strongBox = true)
                    } catch (e: Exception) {
                        // No StrongBox (StrongBoxUnavailableException), or StrongBox refusing the key (some
                        // phones throw a plain ProviderException or reject the spec): fall back to the TEE,
                        // where a real failure surfaces.
                        Timber.i("StrongBox did not make the key (%s); making it in the TEE", e.javaClass.simpleName)
                        runCatching { keyStore.deleteEntry(alias) }
                        generate(alias, strongBox = false)
                    }
                } else {
                    generate(alias, strongBox = false)
                }
            } catch (e: Exception) {
                runCatching { keyStore.deleteEntry(alias) }
                throw KeystoreException("The Android Keystore could not make the key", e, errorCode = "key_generation_failed")
            }
        }
        keyId
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun privateKey(keyId: String): PrivateKey =
        synchronized(keyStore) { keyStore.getKey(alias(keyId), null) as? PrivateKey }
            ?: throw KeystoreException("No Android Keystore key $keyId", errorCode = "key_not_found")

    /**
     * ECDSA P-256 over SHA-256 of [data], in the key's hardware.
     *
     * @return the raw 64-byte `r || s`, `s` in low form.
     * @throws KeystoreException for an unknown key or a failed signature.
     */
    override suspend fun sign(keyId: String, data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val key = privateKey(keyId)
        val der = try {
            Signature.getInstance(SHA256_WITH_ECDSA).run {
                initSign(key)
                update(data)
                sign()
            }
        } catch (e: Exception) {
            throw KeystoreException("The Android Keystore could not sign with $keyId", e, errorCode = "signing_failed")
        }
        EcdsaSignatures.derToRawLowS(der)
    }

    /** This signer's keys (ES256). */
    override suspend fun listKeys(): List<SignerKeyInfo> = withContext(Dispatchers.IO) {
        synchronized(keyStore) {
            keyStore.aliases().toList()
                .filter { it.startsWith(aliasPrefix) }
                .map { it.removePrefix(aliasPrefix) }
                // Only ids this signer makes (UUIDs): another signer whose prefix extends this one
                // ("p." and "p.other.") must not show up here.
                .filter { KEY_ID.matches(it) }
                .map { SignerKeyInfo(keyId = it, algorithm = ES256) }
        }
    }

    /** Deletes the key; deleting a key that does not exist does nothing. */
    override suspend fun deleteKey(keyId: String) = withContext(Dispatchers.IO) {
        synchronized(keyStore) { keyStore.deleteEntry(alias(keyId)) }
    }

    /** Null: Android Key Attestation is not reported by this signer yet. */
    override suspend fun attestationChain(keyId: String): AttestationChain? = null

    /** The public JWK (`kty`, `crv` P-256, `x`, `y`) as UTF-8 JSON. */
    override suspend fun exportPublicKey(keyId: String): ByteArray = withContext(Dispatchers.IO) {
        val certificate = synchronized(keyStore) { keyStore.getCertificate(alias(keyId)) }
            ?: throw KeystoreException("No Android Keystore key $keyId", errorCode = "key_not_found")
        val publicKey = certificate.publicKey as? ECPublicKey
            ?: throw KeystoreException("The Android Keystore key $keyId is not an EC key", errorCode = "key_not_found")
        EcdsaSignatures.publicJwk(publicKey).toByteArray(Charsets.UTF_8)
    }

    /** A hardware key cannot leave its hardware: always [MigrationResult.ReEnrollmentRequired]. */
    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult =
        MigrationResult.ReEnrollmentRequired(keyId)

    /**
     * `keyStorage` from where the Keystore holds the key: `hardware` (StrongBox), `trusted_execution`
     * (TEE), `software`, as [UniFFISigner] names them; no user authentication, no certification.
     */
    override suspend fun securityProperties(keyId: String): SignerSecurityProperties =
        SignerSecurityProperties(
            keyStorage = listOf(keyStorageName(securityLevel(keyId))),
            userAuthentication = emptyList(),
            certification = CertificationInfo.None,
            amr = emptyList(),
        )

    /**
     * Where the Keystore holds [keyId]. Android 12 and later tell StrongBox from the TEE; before
     * that, a hardware key reports [SecurityLevel.TRUSTED_ENVIRONMENT] (never more than is known).
     */
    suspend fun securityLevel(keyId: String): SecurityLevel = withContext(Dispatchers.IO) {
        val key = privateKey(keyId)
        val info = runCatching {
            KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        }.getOrNull() ?: return@withContext SecurityLevel.UNKNOWN
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            levelOf(info.securityLevel)
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) SecurityLevel.TRUSTED_ENVIRONMENT else SecurityLevel.SOFTWARE
        }
    }

    /**
     * The device signature a ZK presentation binds, made with [keyId]: ES256 only (another COSE
     * algorithm is refused rather than substituted, as [ZkWitnessSigner] requires).
     */
    fun zkWitnessSigner(keyId: String): ZkWitnessSigner = ZkWitnessSigner { algorithm, data ->
        if (algorithm != COSE_ALG_ES256) {
            throw KeystoreException(
                "The Android Keystore signer signs ES256 (-7) only, not $algorithm",
                errorCode = "unsupported_algorithm",
            )
        }
        sign(keyId, data)
    }

    companion object {
        /** The default alias prefix. */
        const val DEFAULT_ALIAS_PREFIX: String = "org.siros.sdk.androidkeystore."

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ES256 = "ES256"
        private const val SHA256_WITH_ECDSA = "SHA256withECDSA"
        private val KEY_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

        /** [KeyProperties]' `SECURITY_LEVEL_*` as a [SecurityLevel]. */
        internal fun levelOf(level: Int): SecurityLevel = when (level) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
            else -> SecurityLevel.UNKNOWN
        }

        /** The `keyStorage` name of a [SecurityLevel], the vocabulary [UniFFISigner] reports. */
        internal fun keyStorageName(level: SecurityLevel): String = when (level) {
            SecurityLevel.STRONGBOX -> "hardware"
            SecurityLevel.TRUSTED_ENVIRONMENT -> "trusted_execution"
            SecurityLevel.SOFTWARE, SecurityLevel.UNKNOWN -> "software"
        }
    }
}
