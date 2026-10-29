// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.os.Build
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.KeystoreException
import timber.log.Timber

/**
 * What [AndroidKeystoreSigner] needs from the platform, so the signer's logic is testable without a device. [SystemAndroidKeyStore]
 * is the real one (AndroidKeyStore provider); a fake implementing this interface over an in-memory software key lets every policy,
 * SCA and error-handling path below be exercised on the JVM, including the per-use user-authentication flow (a [Signature] bound to
 * a software key is a real, usable `java.security.Signature`, independent of the Android Keystore provider that issued it).
 */
interface AndroidKeyStoreBackend {
    /** Thrown by [generate] when StrongBox was requested but this device has none (or cannot use it now). */
    class StrongBoxUnavailable(cause: Throwable? = null) : Exception("StrongBox is unavailable", cause)

    /**
     * Generates an EC P-256 SIGN key for SHA-256, origin GENERATED (never imported), optionally bound to [attestationChallenge],
     * and returns the [AndroidKeystoreSigner.SecurityLevel] it was confirmed at. [userAuthenticationMethods] (empty for none)
     * and [unlockedDeviceRequired] are enforced by the Keystore itself for every later use of the key.
     *
     * Before Android 12 the Keystore cannot tell StrongBox apart from the TEE in its own reporting: a key generated with
     * [strongBox] `true` that does not throw is StrongBox (nothing else could have accepted that request), so implementations
     * report [AndroidKeystoreSigner.SecurityLevel.STRONGBOX] for it even pre-12, while a key queried later with no memory of
     * what was requested ([securityLevel]) cannot make that inference and reports the weaker [AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT].
     */
    fun generate(
        alias: String,
        attestationChallenge: ByteArray?,
        strongBox: Boolean,
        userAuthenticationMethods: Set<AndroidKeystoreSigner.AuthenticationMethod> = emptySet(),
        unlockedDeviceRequired: Boolean = true,
    ): AndroidKeystoreSigner.SecurityLevel

    /** The certificate chain of [alias] as DER, leaf first (empty when the alias has none). */
    fun certificateChain(alias: String): List<ByteArray>

    fun publicKey(alias: String): ECPublicKey

    /** Where the Keystore reports [alias] is held NOW (StrongBox distinguished from the TEE only from Android 12). */
    fun securityLevel(alias: String): AndroidKeystoreSigner.SecurityLevel

    /** The per-use authentication [alias] requires, or empty when it needs none. */
    fun userAuthenticationMethods(alias: String): Set<AndroidKeystoreSigner.AuthenticationMethod>

    /**
     * A [Signature] initialized (`initSign`) for signing with [alias]'s private key, not yet executed. For a key that requires
     * user authentication this is the object a [UserAuthenticator] must authenticate (bound to it as a `CryptoObject`) before
     * [Signature.sign] is called; for one that does not, the caller may sign immediately.
     */
    fun newSignature(alias: String): Signature

    fun aliases(): List<String>

    fun delete(alias: String)
}

/**
 * A [Signer] over the Android Keystore: EC P-256 keys that never leave the device's TEE or StrongBox.
 *
 * Two ways to make a key:
 * - [generateAttestedKey] (and the plain [generateKey]) are BEST EFFORT: StrongBox first, the TEE if the device has none,
 *   never refused on the hardware level alone. This is what the wallet's instance-key evidence (the WIA) needs: instance-key
 *   provisioning must succeed on every Android device, including the large majority that have no StrongBox chip.
 * - [createKey] makes a key under an explicit [KeyPolicy]: hardware placement ([KeyPolicy.hardware], StrongBox required by
 *   default), per-use user authentication ([KeyPolicy.userAuthentication]), and whether the phone must be unlocked
 *   ([KeyPolicy.unlockedDeviceRequired]). A key that does not meet its policy is deleted and the call refused - this is for
 *   credential/SCA keys that need a specific, confirmed assurance level, never for the WIA fallback above.
 *
 * [generateAttestedKey] binds a key to an attestation challenge (the wallet instance key's evidence, see the wallet's
 * instance-key attestation) and [attestationChain] returns the chain as DER certificates, LEAF FIRST, in
 * [AttestationChain.FORMAT_ANDROID_KEY]; null for a key that has none (fewer than two certificates). One key per challenge:
 * a retry after a failure uses a NEW key (a new alias) and a new challenge.
 *
 * A key whose policy requires user authentication for every use ([UserAuthentication.EveryUse]) reaches two SCA categories -
 * possession (the key itself) plus inherence (a biometric) or knowledge (the device credential) - see [beginScaSign]. The app
 * supplies the prompt ([UserAuthenticator]; [BiometricPromptAuthenticator] is the ready-made one over `BiometricPrompt`); a
 * key that needs one and has none refuses to sign (`user_authentication_required`).
 *
 * [sign] returns the raw `r || s` (64 bytes, low `s`) that JWS and COSE carry. Origin is always GENERATED: nothing is
 * imported, which is part of what the backend verifies; keys are device-bound, so [migrateKey] always answers
 * [MigrationResult.ReEnrollmentRequired]. A ZK presentation's device signature is this signer like any other: built at the
 * call site as `ZkWitnessSigner { algorithm, data -> keystore.sign(keyId, data) }` over the ordinary [sign] method, through
 * [KeystoreManager]/[WscdKeystoreAdapter] - never a signer-specific shortcut, so nothing can reach a key by a path that
 * bypasses whatever policy lives there.
 *
 * @param backend The platform seam; defaults to the real [SystemAndroidKeyStore]. A test gives its own [AndroidKeyStoreBackend].
 * @param aliasPrefix Prefix of this signer's Android Keystore aliases; a key's id (a UUID by default, see [newAlias]) is the
 *   alias without it. Two signers with different prefixes never see each other's keys, also when one prefix extends the other.
 * @param defaultPolicy The policy [createKey] uses when none is given.
 * @param authenticator Asks the user to authenticate for keys that require it; without one such a key refuses to sign.
 */
class AndroidKeystoreSigner @JvmOverloads constructor(
    private val backend: AndroidKeyStoreBackend = SystemAndroidKeyStore(),
    private val aliasPrefix: String = DEFAULT_ALIAS_PREFIX,
    private val defaultPolicy: KeyPolicy = KeyPolicy(),
    private val authenticator: UserAuthenticator? = null,
    private val newAlias: () -> String = { UUID.randomUUID().toString() },
) : Signer {

    /** Where a key is held, as the Android Keystore reports it. */
    enum class SecurityLevel {
        /** StrongBox: a separate security chip (a Pixel's Titan M2). */
        STRONGBOX,

        /** The TEE (or, before Android 12, "secure hardware" without telling StrongBox apart). */
        TRUSTED_ENVIRONMENT,

        /** A software key (an emulator, a phone without hardware-backed keys). */
        SOFTWARE,

        /** The Keystore did not say. */
        UNKNOWN,
    }

    /** Where a new key made by [createKey] must live; checked when it is made. */
    enum class HardwareRequirement {
        /** StrongBox only (high assurance). A phone without StrongBox cannot make the key. */
        STRONGBOX,

        /** StrongBox if the phone has it, else the TEE; never a software key (lower assurance). */
        HARDWARE,

        /** StrongBox, else the TEE, else whatever the Keystore gives; check [SecurityLevel] via [securityLevel]. */
        ANY,
    }

    /** A way the user authenticates for one use of a key made by [createKey]. */
    enum class AuthenticationMethod {
        /** A strong (class 3) biometric: an inherence factor. */
        BIOMETRIC,

        /** The device PIN, pattern or password: a knowledge factor. Per use from Android 11. */
        DEVICE_CREDENTIAL,
    }

    /** Whether the user authenticates to use a [createKey] key. */
    sealed class UserAuthentication {
        /** No authentication: any code in the app can sign while the policy's other rules hold. */
        data object None : UserAuthentication()

        /**
         * Every single use needs a fresh authentication with one of [methods] (not empty), bound to that use. Needs a secure
         * lock screen, and [AuthenticationMethod.BIOMETRIC] an enrolled strong biometric. [AuthenticationMethod.DEVICE_CREDENTIAL]
         * needs Android 11; before that it is refused alone and dropped beside [AuthenticationMethod.BIOMETRIC].
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
     * How a [createKey] key is made and may be used.
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

    override val supportsAttestedKeyGeneration: Boolean get() = true

    private fun alias(keyId: String) = aliasPrefix + keyId

    private fun requireEs256(algorithm: String) {
        if (!algorithm.equals(ES256, ignoreCase = true)) {
            throw KeystoreException("The Android Keystore signer makes ES256 keys only, not $algorithm", errorCode = "unsupported_algorithm")
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Best effort: StrongBox, else the TEE, never refused on the hardware level. The WIA instance-key flow and the
    // plain Signer.generateKey() contract both need this - they must succeed on every Android device.
    // ---------------------------------------------------------------------------------------------------------------

    override suspend fun generateKey(algorithm: String): String {
        requireEs256(algorithm)
        return generateManaged({ alias(it) }) { bestEffort(null) }
    }

    override suspend fun generateAttestedKey(algorithm: String, attestationChallenge: ByteArray): String {
        requireEs256(algorithm)
        require(attestationChallenge.isNotEmpty()) { "an attestation challenge is required" }
        // Hardware key generation (StrongBox, attestation provisioning) can block for seconds: never on the caller's (main) dispatcher.
        return generateManaged({ alias(it) }) { bestEffort(attestationChallenge) }
    }

    /**
     * Makes a key bound to [challenge] (or none), asking for StrongBox first and falling back to a NEW alias in the TEE if
     * the device has none - never refused on the resulting hardware level, unlike [createKey]. [unlockedDeviceRequired] is
     * left at the Keystore's own default (not required) to preserve the instance-key flow's original behavior exactly:
     * a key made here is never policy-gated on the phone being unlocked.
     */
    private fun bestEffort(challenge: ByteArray?): String {
        val keyId = newAlias()
        try {
            backend.generate(alias(keyId), challenge, strongBox = true, unlockedDeviceRequired = false)
        } catch (e: AndroidKeyStoreBackend.StrongBoxUnavailable) {
            // No StrongBox: the TEE, on a NEW alias (a half-made StrongBox key must not be reused).
            backend.delete(alias(keyId))
            val tee = newAlias()
            backend.generate(alias(tee), challenge, strongBox = false, unlockedDeviceRequired = false)
            return tee
        }
        return keyId
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Explicit policy: hardware, user authentication and lock-state requirements are all enforced, with refusal.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Makes a P-256 key under [policy] (the signer's [defaultPolicy] when none is given) and confirms where it is held. A
     * key below [KeyPolicy.hardware] is deleted again and refused.
     *
     * @throws KeystoreException `strongbox_unavailable` (StrongBox required and the phone has none, or the key is not
     *   confirmed in it), `hardware_unavailable` (hardware required, the Keystore gave a software key),
     *   `user_authentication_unsupported` (device credential alone before Android 11), or `key_generation_failed` (for
     *   example a user-authentication key without a secure lock screen).
     */
    suspend fun createKey(policy: KeyPolicy = defaultPolicy): CreatedKey = generateManaged({ alias(it.keyId) }) {
        val methods = effectiveMethods(policy.userAuthentication, Build.VERSION.SDK_INT)
        if (policy.userAuthentication is UserAuthentication.EveryUse && methods.isEmpty()) {
            throw KeystoreException("The device credential as a per-use factor needs Android 11", errorCode = "user_authentication_unsupported")
        }
        val keyId = newAlias()
        val a = alias(keyId)
        val level = try {
            makeKey(a, policy, methods)
        } catch (e: KeystoreException) {
            runCatching { backend.delete(a) }
            throw e
        } catch (e: Exception) {
            runCatching { backend.delete(a) }
            throw KeystoreException("The Android Keystore could not make the key: ${e.message}", e, errorCode = "key_generation_failed")
        }
        if (!meets(level, policy.hardware)) {
            backend.delete(a)
            throw KeystoreException(
                "The key landed in $level, below the required ${policy.hardware}",
                errorCode = if (policy.hardware == HardwareRequirement.STRONGBOX) "strongbox_unavailable" else "hardware_unavailable",
            )
        }
        CreatedKey(keyId, level)
    }

    /** Makes the key under [alias] and returns the level it was confirmed at. */
    private fun makeKey(alias: String, policy: KeyPolicy, methods: Set<AuthenticationMethod>): SecurityLevel {
        if (policy.hardware == HardwareRequirement.STRONGBOX) {
            return try {
                backend.generate(alias, null, strongBox = true, userAuthenticationMethods = methods, unlockedDeviceRequired = policy.unlockedDeviceRequired)
            } catch (e: AndroidKeyStoreBackend.StrongBoxUnavailable) {
                throw KeystoreException("This phone has no StrongBox", e, errorCode = "strongbox_unavailable")
            }
            // Any other failure (StrongBox refusing the spec, no secure lock screen for a user-authentication key)
            // surfaces from createKey as key_generation_failed, with its message.
        }
        try {
            return backend.generate(alias, null, strongBox = true, userAuthenticationMethods = methods, unlockedDeviceRequired = policy.unlockedDeviceRequired)
        } catch (e: Exception) {
            // No StrongBox (StrongBoxUnavailable), or StrongBox refusing the key (some phones throw a plain
            // exception rather than StrongBoxUnavailable): the TEE, where a real failure surfaces.
            Timber.i("StrongBox did not make the key (%s); making it in the TEE", e.javaClass.simpleName)
            runCatching { backend.delete(alias) }
        }
        return backend.generate(alias, null, strongBox = false, userAuthenticationMethods = methods, unlockedDeviceRequired = policy.unlockedDeviceRequired)
    }

    /**
     * Runs [make] (a blocking call) on [Dispatchers.IO] and returns its result even if THIS call is cancelled exactly at the
     * dispatcher handoff back to the caller: Android Keystore has already persisted the key by the time [make] returns, a
     * plain `withContext(Dispatchers.IO) { make() }` can still throw [CancellationException] instead of returning it if the
     * parent job was cancelled in the meantime, and losing the result that way would leak an untracked hardware key forever
     * (StrongBox/TEE key storage is finite - enough cancelled attempts, e.g. the app backgrounded during a slow attestation,
     * could exhaust it for every key on the device, not only instance keys). If genuinely cancelled, the orphaned key named
     * by [aliasOf] is deleted instead, in a [NonCancellable] cleanup so the deletion itself cannot be cut short by the same
     * cancellation. Applies to every key-generation entry point: the best-effort path, [createKey], all of it.
     */
    private suspend fun <T> generateManaged(aliasOf: (T) -> String, make: () -> T): T {
        var created: T? = null
        return try {
            withContext(Dispatchers.IO) { make().also { created = it } }
        } catch (e: CancellationException) {
            created?.let { t ->
                withContext(NonCancellable) { runCatching { backend.delete(aliasOf(t)) } }
            }
            throw e
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Signing, listing, attestation, security properties - common to both ways of making a key.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * ECDSA P-256 over SHA-256 of [data], in the key's hardware. A key that requires user authentication (made by
     * [createKey] with [UserAuthentication.EveryUse]) asks the [authenticator] first, for this signature alone.
     *
     * @return the raw 64-byte `r || s`, `s` in low form.
     * @throws KeystoreException `key_not_found`, `user_authentication_required` (no authenticator), the authenticator's
     *   failure, or `signing_failed` (including a key used while the phone is locked).
     */
    override suspend fun sign(keyId: String, data: ByteArray): ByteArray {
        val methods = withContext(Dispatchers.IO) { userAuthenticationMethodsOf(keyId) }
        val signature = withContext(Dispatchers.IO) { newSignature(keyId) }
        if (methods.isNotEmpty()) authenticate(keyId, methods, signature)
        return withContext(Dispatchers.IO) { finish(keyId, signature, data) }
    }

    private fun userAuthenticationMethodsOf(keyId: String): Set<AuthenticationMethod> {
        ensureExists(keyId)
        return backend.userAuthenticationMethods(alias(keyId))
    }

    private fun ensureExists(keyId: String) {
        if (alias(keyId) !in backend.aliases()) throw KeystoreException("No Android Keystore key $keyId", errorCode = "key_not_found")
    }

    private fun newSignature(keyId: String): Signature {
        ensureExists(keyId)
        return try {
            backend.newSignature(alias(keyId))
        } catch (e: KeystoreException) {
            throw e
        } catch (e: Exception) {
            throw KeystoreException("The Android Keystore could not start a signature with $keyId (${e.javaClass.simpleName})", e, errorCode = "signing_failed")
        }
    }

    private suspend fun authenticate(keyId: String, methods: Set<AuthenticationMethod>, signature: Signature): AuthenticationMethod {
        val auth = authenticator
            ?: throw KeystoreException("The key $keyId requires user authentication and no authenticator was given", errorCode = "user_authentication_required")
        val used = auth.authenticate(UserAuthenticationRequest(keyId, methods, signature))
        if (used !in methods) {
            throw KeystoreException("The user authenticated with $used, which the key does not allow", errorCode = "user_authentication_failed")
        }
        return used
    }

    private fun finish(keyId: String, signature: Signature, data: ByteArray): ByteArray {
        val der = try {
            signature.update(data)
            signature.sign()
        } catch (e: Exception) {
            throw KeystoreException("The Android Keystore could not sign with $keyId (${e.javaClass.simpleName})", e, errorCode = "signing_failed")
        }
        return EcdsaSignatures.derToRawLowS(der)
    }

    /**
     * This signer's keys (ES256), under its own [aliasPrefix] only. The [KEY_ID] filter (not just [aliasPrefix])
     * matters when one signer's prefix extends another's ("p." and "p.other."): stripping "p." from "p.other.<id>"
     * leaves "other.<id>", which is not a bare id and so is excluded - without it, a signer would also see every key
     * of every OTHER signer whose prefix happens to start with its own.
     */
    override suspend fun listKeys(): List<SignerKeyInfo> = withContext(Dispatchers.IO) {
        backend.aliases()
            .filter { it.startsWith(aliasPrefix) }
            .map { it.removePrefix(aliasPrefix) }
            .filter { KEY_ID.matches(it) }
            .map { SignerKeyInfo(keyId = it, algorithm = ES256) }
    }

    /** Deletes the key; deleting a key that does not exist does nothing. */
    override suspend fun deleteKey(keyId: String): Unit = withContext(Dispatchers.IO) { backend.delete(alias(keyId)) }

    /**
     * The attestation chain as DER certificates, LEAF FIRST, in [AttestationChain.FORMAT_ANDROID_KEY]; null for a key with
     * fewer than two certificates (Android Key Attestation was not available when the key was made).
     */
    override suspend fun attestationChain(keyId: String): AttestationChain? = withContext(Dispatchers.IO) {
        val chain = backend.certificateChain(alias(keyId))
        if (chain.size >= 2) AttestationChain(chain, ByteArray(0), AttestationChain.FORMAT_ANDROID_KEY) else null
    }

    /**
     * `kid` is the exported key id: `WscdKeystoreAdapter` embeds this JWK unchanged into a credential proof, and
     * `SirosWallet.extractProofKeyId` reads it back from `kid`/`jwk.kid` to recover the holder key a multi-key mdoc batch
     * was proved with. Without it an embedded-JWK proof loses that binding and verification can fall back to the wrong key.
     */
    override suspend fun exportPublicKey(keyId: String): ByteArray = withContext(Dispatchers.IO) {
        ensureExists(keyId)
        val key = backend.publicKey(alias(keyId))
        EcdsaSignatures.publicJwk(key, kid = keyId).toByteArray(Charsets.UTF_8)
    }

    /** A hardware key cannot leave its hardware: always [MigrationResult.ReEnrollmentRequired]. */
    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult = MigrationResult.ReEnrollmentRequired(keyId)

    /**
     * `keyStorage` from where the Keystore holds the key: `hardware` (StrongBox), `trusted_execution` (TEE), `software`, as
     * [UniFFISigner] names them; `userAuthentication` the methods each use needs (`biometric`, `device_credential`; empty
     * for none); no certification.
     */
    override suspend fun securityProperties(keyId: String): SignerSecurityProperties = withContext(Dispatchers.IO) {
        ensureExists(keyId)
        val level = backend.securityLevel(alias(keyId))
        val methods = backend.userAuthenticationMethods(alias(keyId))
        SignerSecurityProperties(
            keyStorage = listOf(keyStorageName(level)),
            userAuthentication = methods.map { userAuthenticationName(it) }.sorted(),
            certification = CertificationInfo.None,
        )
    }

    /** Where the Keystore holds [keyId] right now (Android 12+ tell StrongBox from the TEE; before that a hardware key reports [SecurityLevel.TRUSTED_ENVIRONMENT]). */
    suspend fun securityLevel(keyId: String): SecurityLevel = withContext(Dispatchers.IO) {
        ensureExists(keyId)
        backend.securityLevel(alias(keyId))
    }

    /**
     * Two SCA categories are possible for a key that requires user authentication for every use, when an [authenticator]
     * was given: possession (the key) and inherence or knowledge. Never prompts.
     */
    override suspend fun scaAuthenticationCapability(keyId: String): ScaAuthenticationCapability {
        val methods = try {
            withContext(Dispatchers.IO) { userAuthenticationMethodsOf(keyId) }
        } catch (e: KeystoreException) {
            return ScaAuthenticationCapability.cannot("The key is not available")
        }
        return when {
            methods.isEmpty() -> ScaAuthenticationCapability.cannot("The key needs no user authentication: possession only")
            authenticator == null -> ScaAuthenticationCapability.cannot("No user authenticator was given")
            else -> ScaAuthenticationCapability(canReachTwoCategories = true)
        }
    }

    /**
     * One SCA sign: the user authenticates NOW (after consent, before the claims are fixed), so the factors are known
     * ([ScaSignSession.declaredFactors]: possession plus the method used), and the session's one [ScaSignSession.sign]
     * uses that authentication. A key without user authentication, or no [authenticator], is refused.
     */
    override suspend fun beginScaSign(keyId: String): ScaSignSession {
        val capability = scaAuthenticationCapability(keyId)
        if (!capability.isPossible) throw ScaSignSession.insufficient(capability.reason ?: "SCA is not possible with this key")
        val methods = withContext(Dispatchers.IO) { userAuthenticationMethodsOf(keyId) }
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

    companion object {
        /** The default alias prefix. */
        const val DEFAULT_ALIAS_PREFIX: String = "org.siros.sdk.androidkeystore."

        /**
         * The TS12 possession method a key in the phone's own secure hardware reports (`key_in_local_native_wscd`). To be
         * confirmed against TS12 v1.0.1 3.6.
         */
        const val POSSESSION_METHOD: String = "key_in_local_native_wscd"

        private const val ES256 = "ES256"

        /**
         * What a bare key id made by [newAlias]'s default looks like (a UUID), used by [listKeys] to tell this
         * signer's own keys apart from another signer's whose prefix happens to extend this one's. A custom
         * [newAlias] producing ids of a different shape still works for every other operation (they all key off the
         * full `aliasPrefix + keyId`); only such a signer's own [listKeys] would need a matching custom filter, which
         * this class does not need in practice (every production caller uses the default [newAlias]).
         */
        private val KEY_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

        /** Whether [level] satisfies [requirement]. */
        internal fun meets(level: SecurityLevel, requirement: HardwareRequirement): Boolean = when (requirement) {
            HardwareRequirement.STRONGBOX -> level == SecurityLevel.STRONGBOX
            HardwareRequirement.HARDWARE -> level == SecurityLevel.STRONGBOX || level == SecurityLevel.TRUSTED_ENVIRONMENT
            HardwareRequirement.ANY -> true
        }

        /**
         * The methods a key gets on Android [sdk]: none for [UserAuthentication.None]; before Android 11 the device
         * credential is dropped (and a set of only it becomes empty: refused).
         */
        internal fun effectiveMethods(auth: UserAuthentication, sdk: Int): Set<AuthenticationMethod> = when (auth) {
            UserAuthentication.None -> emptySet()
            is UserAuthentication.EveryUse ->
                if (sdk >= Build.VERSION_CODES.R) auth.methods else auth.methods - AuthenticationMethod.DEVICE_CREDENTIAL
        }

        /** `android.security.keystore.KeyProperties`' `AUTH_*` flags for [methods]. */
        internal fun keystoreAuthTypes(methods: Set<AuthenticationMethod>): Int {
            var types = 0
            if (AuthenticationMethod.BIOMETRIC in methods) types = types or android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG
            if (AuthenticationMethod.DEVICE_CREDENTIAL in methods) types = types or android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL
            return types
        }

        /** The methods in `KeyProperties`' `AUTH_*` flags [types]. */
        internal fun methodsOf(types: Int): Set<AuthenticationMethod> = buildSet {
            if (types and android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG != 0) add(AuthenticationMethod.BIOMETRIC)
            if (types and android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL != 0) add(AuthenticationMethod.DEVICE_CREDENTIAL)
        }

        /** `android.security.keystore.KeyProperties`' `SECURITY_LEVEL_*` as a [SecurityLevel]. */
        internal fun levelOf(level: Int): SecurityLevel = when (level) {
            android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
            android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
            android.security.keystore.KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
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
