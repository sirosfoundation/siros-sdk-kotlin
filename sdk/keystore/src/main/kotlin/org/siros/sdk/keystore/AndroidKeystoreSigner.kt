// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
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
 * A [Signer] over the Android Keystore: P-256 (ES256) keys in the phone's secure hardware, each
 * made under a [KeyPolicy]:
 *
 * - **Where the key lives** ([HardwareRequirement]): StrongBox, the phone's separate security chip
 *   (a Pixel's Titan M2), by default, as high-assurance keys need; the TEE where lower assurance
 *   is enough; anything only when asked. The level is confirmed when the key is made, and a key
 *   below the requirement is deleted and refused, so a key that exists meets its requirement.
 * - **Who may use it** ([UserAuthentication]): nobody needs to authenticate ([UserAuthentication.None],
 *   for a demo), or the user authenticates for every single use ([UserAuthentication.EveryUse]):
 *   a strong biometric, the device PIN/pattern/password, or either, as the key's policy says. The
 *   Keystore enforces it in the hardware; the app supplies the prompt ([UserAuthenticator],
 *   [BiometricPromptAuthenticator]). Such a key reaches two SCA categories: possession (the key)
 *   and inherence (biometric) or knowledge (device credential), see [beginScaSign].
 * - **When** ([KeyPolicy.unlockedDeviceRequired]): not while the phone is locked, by default.
 *
 * [sign] returns the raw `r || s` that JWS and COSE carry, with `s` in low form. The keys are
 * device-bound: nothing is exported, a key cannot move to another plugin ([migrateKey] answers
 * re-enrollment), and uninstalling the app deletes them. [zkWitnessSigner] is the device signature
 * a ZK presentation binds ([CircuitZkPresenter.present]).
 *
 * Not in this class (yet): Android Key Attestation ([attestationChain] returns null).
 *
 * @param aliasPrefix Prefix of this signer's Android Keystore aliases; a key's id (a UUID) is the
 *   alias without it. Two signers with different prefixes never see each other's keys, also when
 *   one prefix extends the other.
 * @param defaultPolicy The policy [generateKey] makes keys under ([createKey] takes its own).
 * @param authenticator Asks the user to authenticate for keys that require it; without one such a
 *   key refuses to sign (`user_authentication_required`).
 */
class AndroidKeystoreSigner @JvmOverloads constructor(
    private val aliasPrefix: String = DEFAULT_ALIAS_PREFIX,
    private val defaultPolicy: KeyPolicy = KeyPolicy(),
    private val authenticator: UserAuthenticator? = null,
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

    /** Where a new key must live; checked when it is made. */
    enum class HardwareRequirement {
        /** StrongBox only (high assurance). A phone without StrongBox cannot make the key. */
        STRONGBOX,

        /** StrongBox if the phone has it, else the TEE; never a software key (lower assurance). */
        HARDWARE,

        /** StrongBox, else the TEE, else whatever the Keystore gives; check [securityLevel]. */
        ANY,
    }

    /** A way the user authenticates for one use of a key. */
    enum class AuthenticationMethod {
        /** A strong (class 3) biometric: an inherence factor. */
        BIOMETRIC,

        /** The device PIN, pattern or password: a knowledge factor. Per use from Android 11. */
        DEVICE_CREDENTIAL,
    }

    /** Whether the user authenticates to use a key. */
    sealed class UserAuthentication {
        /** No authentication: any code in the app can sign while the policy's other rules hold. */
        data object None : UserAuthentication()

        /**
         * Every single use needs a fresh authentication with one of [methods] (not empty), bound to
         * that use. Needs a secure lock screen, and [AuthenticationMethod.BIOMETRIC] an enrolled
         * strong biometric. [AuthenticationMethod.DEVICE_CREDENTIAL] needs Android 11; before
         * that it is refused alone and dropped beside [AuthenticationMethod.BIOMETRIC].
         */
        data class EveryUse(
            val methods: Set<AuthenticationMethod> = setOf(AuthenticationMethod.BIOMETRIC, AuthenticationMethod.DEVICE_CREDENTIAL),
        ) : UserAuthentication() {
            init {
                require(methods.isNotEmpty()) { "EveryUse needs at least one authentication method" }
            }
        }
    }

    /**
     * How a key is made and may be used.
     *
     * @property hardware Where it must live (default StrongBox).
     * @property userAuthentication Whether each use needs the user (default none).
     * @property unlockedDeviceRequired No signing while the phone is locked (default on).
     */
    data class KeyPolicy(
        val hardware: HardwareRequirement = HardwareRequirement.STRONGBOX,
        val userAuthentication: UserAuthentication = UserAuthentication.None,
        val unlockedDeviceRequired: Boolean = true,
    )

    /** A key [createKey] made: its id and where the Keystore confirmed it is held. */
    data class CreatedKey(val keyId: String, val securityLevel: SecurityLevel)

    init {
        require(aliasPrefix.isNotEmpty()) { "aliasPrefix must not be empty" }
    }

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } }

    private fun alias(keyId: String) = aliasPrefix + keyId

    /**
     * Makes a key under the signer's default policy.
     *
     * @param algorithm `ES256` only.
     * @return the key id.
     * @throws KeystoreException as [createKey], or `unsupported_algorithm`.
     */
    override suspend fun generateKey(algorithm: String): String {
        if (!algorithm.equals(ES256, ignoreCase = true)) {
            throw KeystoreException(
                "The Android Keystore signer makes ES256 keys only, not $algorithm",
                errorCode = "unsupported_algorithm",
            )
        }
        return createKey(defaultPolicy).keyId
    }

    /**
     * Makes a P-256 key under [policy] and confirms where it is held. A key below
     * [KeyPolicy.hardware] is deleted again and refused.
     *
     * @throws KeystoreException `strongbox_unavailable` (StrongBox required and the phone has none, or
     *   the key is not confirmed in it), `hardware_unavailable` (hardware required, the Keystore gave a software key),
     *   `user_authentication_unsupported` (device credential alone before Android 11), or
     *   `key_generation_failed` (for example a user-authentication key without a secure lock screen).
     */
    suspend fun createKey(policy: KeyPolicy = defaultPolicy): CreatedKey = withContext(Dispatchers.IO) {
        val methods = effectiveMethods(policy.userAuthentication, Build.VERSION.SDK_INT)
        if (policy.userAuthentication is UserAuthentication.EveryUse && methods.isEmpty()) {
            throw KeystoreException(
                "The device credential as a per-use factor needs Android 11",
                errorCode = "user_authentication_unsupported",
            )
        }
        val keyId = UUID.randomUUID().toString()
        val alias = alias(keyId)
        synchronized(keyStore) {
            val level = try {
                makeKey(alias, policy, methods)
            } catch (e: KeystoreException) {
                runCatching { keyStore.deleteEntry(alias) }
                throw e
            } catch (e: Exception) {
                runCatching { keyStore.deleteEntry(alias) }
                throw KeystoreException("The Android Keystore could not make the key: ${e.message}", e, errorCode = "key_generation_failed")
            }
            if (!meets(level, policy.hardware)) {
                keyStore.deleteEntry(alias)
                throw KeystoreException(
                    "The key landed in $level, below the required ${policy.hardware}",
                    errorCode = if (policy.hardware == HardwareRequirement.STRONGBOX) "strongbox_unavailable" else "hardware_unavailable",
                )
            }
            CreatedKey(keyId, level)
        }
    }

    /** Makes the key and returns the level it was confirmed at. */
    private fun makeKey(alias: String, policy: KeyPolicy, methods: Set<AuthenticationMethod>): SecurityLevel {
        if (policy.hardware == HardwareRequirement.STRONGBOX) {
            try {
                generate(alias, policy, methods, strongBox = true)
            } catch (e: StrongBoxUnavailableException) {
                throw KeystoreException("This phone has no StrongBox", e, errorCode = "strongbox_unavailable")
            }
            // Any other failure (StrongBox refusing the spec, no secure lock screen for a user-authentication
            // key) surfaces from createKey as key_generation_failed, with its message.
            return confirmedStrongBoxLevel(alias)
        }
        try {
            generate(alias, policy, methods, strongBox = true)
            return confirmedStrongBoxLevel(alias)
        } catch (e: Exception) {
            // No StrongBox (StrongBoxUnavailableException), or StrongBox refusing the key (some phones
            // throw a plain ProviderException or reject the spec): the TEE, where a real failure surfaces.
            Timber.i("StrongBox did not make the key (%s); making it in the TEE", e.javaClass.simpleName)
            runCatching { keyStore.deleteEntry(alias) }
        }
        generate(alias, policy, methods, strongBox = false)
        return levelReported(alias) ?: SecurityLevel.UNKNOWN
    }

    /**
     * The level of a key made with `setIsStrongBoxBacked(true)` (which throws
     * `StrongBoxUnavailableException` rather than make it elsewhere). Android 12+ reports StrongBox
     * itself and is believed; before, the Keystore can only say "secure hardware", which for such a
     * key is StrongBox. Anything weaker reported is taken as is, so the requirement check refuses it.
     */
    private fun confirmedStrongBoxLevel(alias: String): SecurityLevel {
        val reported = levelReported(alias) ?: return SecurityLevel.UNKNOWN
        return if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S && reported == SecurityLevel.TRUSTED_ENVIRONMENT) {
            SecurityLevel.STRONGBOX
        } else {
            reported
        }
    }

    private fun generate(alias: String, policy: KeyPolicy, methods: Set<AuthenticationMethod>, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .setUnlockedDeviceRequired(policy.unlockedDeviceRequired)
            .apply {
                if (policy.userAuthentication is UserAuthentication.EveryUse) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        // Timeout 0: one authentication per use, bound to that use's CryptoObject.
                        setUserAuthenticationParameters(0, keystoreAuthTypes(methods))
                    } else {
                        // Before Android 11, -1 means: a biometric for every use.
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                    }
                }
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun privateKey(keyId: String): PrivateKey =
        synchronized(keyStore) { keyStore.getKey(alias(keyId), null) as? PrivateKey }
            ?: throw KeystoreException("No Android Keystore key $keyId", errorCode = "key_not_found")

    private fun keyInfo(key: PrivateKey): KeyInfo? = runCatching {
        KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
    }.getOrNull()

    /** What the Keystore reports for the key under [alias] (StrongBox only from Android 12). */
    private fun levelReported(alias: String): SecurityLevel? {
        val key = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val info = keyInfo(key) ?: return null
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            levelOf(info.securityLevel)
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) SecurityLevel.TRUSTED_ENVIRONMENT else SecurityLevel.SOFTWARE
        }
    }

    /** The methods the key at [keyId] accepts per use, or null when it needs no authentication. */
    private fun authenticationOf(keyId: String): Set<AuthenticationMethod>? {
        val info = keyInfo(privateKey(keyId))
            ?: throw KeystoreException("The Android Keystore did not describe $keyId", errorCode = "key_not_found")
        if (!info.isUserAuthenticationRequired) return null
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            methodsOf(info.userAuthenticationType)
        } else {
            setOf(AuthenticationMethod.BIOMETRIC)
        }
    }

    /**
     * ECDSA P-256 over SHA-256 of [data], in the key's hardware. A key that requires user
     * authentication asks the [authenticator] first, for this signature alone.
     *
     * @return the raw 64-byte `r || s`, `s` in low form.
     * @throws KeystoreException `key_not_found`, `user_authentication_required` (no authenticator),
     *   the authenticator's failure, or `signing_failed` (including a key used while the phone is locked).
     */
    override suspend fun sign(keyId: String, data: ByteArray): ByteArray {
        val methods = withContext(Dispatchers.IO) { authenticationOf(keyId) }
        val signature = withContext(Dispatchers.IO) { newSignature(keyId) }
        if (methods != null) authenticate(keyId, methods, signature)
        return withContext(Dispatchers.IO) { finish(keyId, signature, data) }
    }

    private fun newSignature(keyId: String): Signature = try {
        Signature.getInstance(SHA256_WITH_ECDSA).apply { initSign(privateKey(keyId)) }
    } catch (e: KeystoreException) {
        throw e
    } catch (e: Exception) {
        throw KeystoreException(
            "The Android Keystore could not start a signature with $keyId (${e.javaClass.simpleName})",
            e,
            errorCode = "signing_failed",
        )
    }

    private suspend fun authenticate(keyId: String, methods: Set<AuthenticationMethod>, signature: Signature): AuthenticationMethod {
        val auth = authenticator ?: throw KeystoreException(
            "The key $keyId requires user authentication and no authenticator was given",
            errorCode = "user_authentication_required",
        )
        val used = auth.authenticate(UserAuthenticationRequest(keyId, methods, signature))
        if (used !in methods) {
            throw KeystoreException(
                "The user authenticated with $used, which the key does not allow",
                errorCode = "user_authentication_failed",
            )
        }
        return used
    }

    private fun finish(keyId: String, signature: Signature, data: ByteArray): ByteArray {
        val der = try {
            signature.update(data)
            signature.sign()
        } catch (e: Exception) {
            throw KeystoreException(
                "The Android Keystore could not sign with $keyId (${e.javaClass.simpleName})",
                e,
                errorCode = "signing_failed",
            )
        }
        return EcdsaSignatures.derToRawLowS(der)
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
     * (TEE), `software`, as [UniFFISigner] names them; `userAuthentication` the methods each use
     * needs (`biometric`, `device_credential`; empty for none); no certification.
     */
    override suspend fun securityProperties(keyId: String): SignerSecurityProperties {
        val level = securityLevel(keyId)
        val methods = withContext(Dispatchers.IO) { authenticationOf(keyId) }.orEmpty()
        return SignerSecurityProperties(
            keyStorage = listOf(keyStorageName(level)),
            userAuthentication = methods.map { userAuthenticationName(it) }.sorted(),
            certification = CertificationInfo.None,
            amr = emptyList(),
        )
    }

    /**
     * Where the Keystore holds [keyId]. Android 12 and later tell StrongBox from the TEE; before
     * that, a hardware key reports [SecurityLevel.TRUSTED_ENVIRONMENT] (never more than is known;
     * [createKey] reports the level confirmed when the key was made).
     */
    suspend fun securityLevel(keyId: String): SecurityLevel = withContext(Dispatchers.IO) {
        privateKey(keyId)
        synchronized(keyStore) { levelReported(alias(keyId)) } ?: SecurityLevel.UNKNOWN
    }

    /**
     * Two SCA categories are possible for a key that requires user authentication for every use,
     * when an [authenticator] was given: possession (the key) and inherence or knowledge. Never prompts.
     */
    override suspend fun scaAuthenticationCapability(keyId: String): ScaAuthenticationCapability {
        val methods = try {
            withContext(Dispatchers.IO) { authenticationOf(keyId) }
        } catch (e: KeystoreException) {
            return ScaAuthenticationCapability.cannot("The key is not available")
        }
        return when {
            methods == null -> ScaAuthenticationCapability.cannot("The key needs no user authentication: possession only")
            authenticator == null -> ScaAuthenticationCapability.cannot("No user authenticator was given")
            else -> ScaAuthenticationCapability(canReachTwoCategories = true)
        }
    }

    /**
     * One SCA sign: the user authenticates NOW (after consent, before the claims are fixed), so the
     * factors are known ([ScaSignSession.declaredFactors]: possession plus the method used), and the
     * session's one [ScaSignSession.sign] uses that authentication. A key without user
     * authentication, or no [authenticator], is refused.
     */
    override suspend fun beginScaSign(keyId: String): ScaSignSession {
        val capability = scaAuthenticationCapability(keyId)
        if (!capability.isPossible) throw ScaSignSession.insufficient(capability.reason ?: "SCA is not possible with this key")
        val methods = withContext(Dispatchers.IO) { authenticationOf(keyId) }!!
        val signature = withContext(Dispatchers.IO) { newSignature(keyId) }
        val used = authenticate(keyId, methods, signature)
        val factors = scaFactors(used)
        return object : ScaSignSession {
            private var spent = false
            override val declaredFactors: List<AuthenticationFactor> = factors

            override suspend fun sign(data: ByteArray): ScaSignature {
                check(!spent) { "An SCA sign session signs once" }
                spent = true
                return ScaSignature(withContext(Dispatchers.IO) { finish(keyId, signature, data) }, factors)
            }
        }
    }

    /**
     * The device signature a ZK presentation binds, made with [keyId]: ES256 only (another COSE
     * algorithm is refused rather than substituted, as [ZkWitnessSigner] requires). A key that
     * requires user authentication prompts, as [sign] does.
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

        /**
         * The TS12 possession method a key in the phone's own secure hardware reports
         * (`key_in_local_native_wscd`). To be confirmed against TS12 v1.0.1 3.6.
         */
        const val POSSESSION_METHOD: String = "key_in_local_native_wscd"

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

        internal fun userAuthenticationName(method: AuthenticationMethod): String = when (method) {
            AuthenticationMethod.BIOMETRIC -> "biometric"
            AuthenticationMethod.DEVICE_CREDENTIAL -> "device_credential"
        }

        /** Whether [level] satisfies [requirement]. */
        internal fun meets(level: SecurityLevel, requirement: HardwareRequirement): Boolean = when (requirement) {
            HardwareRequirement.STRONGBOX -> level == SecurityLevel.STRONGBOX
            HardwareRequirement.HARDWARE -> level == SecurityLevel.STRONGBOX || level == SecurityLevel.TRUSTED_ENVIRONMENT
            HardwareRequirement.ANY -> true
        }

        /**
         * The methods a key gets on Android [sdk]: none for [UserAuthentication.None]; before Android 11
         * the device credential is dropped (and a set of only it becomes empty: refused).
         */
        internal fun effectiveMethods(auth: UserAuthentication, sdk: Int): Set<AuthenticationMethod> = when (auth) {
            UserAuthentication.None -> emptySet()
            is UserAuthentication.EveryUse ->
                if (sdk >= Build.VERSION_CODES.R) auth.methods else auth.methods - AuthenticationMethod.DEVICE_CREDENTIAL
        }

        /** [KeyProperties]' `AUTH_*` flags for [methods]. */
        internal fun keystoreAuthTypes(methods: Set<AuthenticationMethod>): Int {
            var types = 0
            if (AuthenticationMethod.BIOMETRIC in methods) types = types or KeyProperties.AUTH_BIOMETRIC_STRONG
            if (AuthenticationMethod.DEVICE_CREDENTIAL in methods) types = types or KeyProperties.AUTH_DEVICE_CREDENTIAL
            return types
        }

        /** The methods in [KeyProperties]' `AUTH_*` flags [types]. */
        internal fun methodsOf(types: Int): Set<AuthenticationMethod> = buildSet {
            if (types and KeyProperties.AUTH_BIOMETRIC_STRONG != 0) add(AuthenticationMethod.BIOMETRIC)
            if (types and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0) add(AuthenticationMethod.DEVICE_CREDENTIAL)
        }

        /** The SCA factors of a sign with [method]: possession (this key) and the user's factor. */
        internal fun scaFactors(method: AuthenticationMethod): List<AuthenticationFactor> = listOf(
            AuthenticationFactor(AuthenticationCategory.POSSESSION, POSSESSION_METHOD),
            when (method) {
                // Android does not say which biometric (fingerprint, face) or credential (PIN, pattern, password).
                AuthenticationMethod.BIOMETRIC -> AuthenticationFactor(AuthenticationCategory.INHERENCE, "other")
                AuthenticationMethod.DEVICE_CREDENTIAL -> AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "other")
            },
        )
    }
}
