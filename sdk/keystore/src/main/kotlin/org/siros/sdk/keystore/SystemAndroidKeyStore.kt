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

/** The real [AndroidKeyStoreBackend]: the `AndroidKeyStore` provider. Needs a device (or emulator); see the instrumented tests. */
class SystemAndroidKeyStore : AndroidKeyStoreBackend {
    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun generate(
        alias: String,
        attestationChallenge: ByteArray?,
        strongBox: Boolean,
        userAuthenticationMethods: Set<AndroidKeystoreSigner.AuthenticationMethod>,
        unlockedDeviceRequired: Boolean,
    ): AndroidKeystoreSigner.SecurityLevel {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUnlockedDeviceRequired(unlockedDeviceRequired)
        if (attestationChallenge != null) builder.setAttestationChallenge(attestationChallenge)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        if (userAuthenticationMethods.isNotEmpty()) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Timeout 0: one authentication per use, bound to that use's CryptoObject.
                builder.setUserAuthenticationParameters(0, AndroidKeystoreSigner.keystoreAuthTypes(userAuthenticationMethods))
            } else {
                // Before Android 11, -1 means: a biometric for every use.
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        }
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                .apply { initialize(builder.build()) }
                .generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            throw AndroidKeyStoreBackend.StrongBoxUnavailable(e)
        }
        return confirmedLevel(alias, strongBoxRequested = strongBox)
    }

    override fun certificateChain(alias: String): List<ByteArray> =
        store().getCertificateChain(alias)?.map { it.encoded }.orEmpty()

    override fun publicKey(alias: String): ECPublicKey = store().getCertificate(alias).publicKey as ECPublicKey

    override fun securityLevel(alias: String): AndroidKeystoreSigner.SecurityLevel = rawLevel(alias) ?: AndroidKeystoreSigner.SecurityLevel.UNKNOWN

    override fun userAuthenticationMethods(alias: String): Set<AndroidKeystoreSigner.AuthenticationMethod> {
        val info = keyInfo(alias) ?: return emptySet()
        if (!info.isUserAuthenticationRequired) return emptySet()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            AndroidKeystoreSigner.methodsOf(info.userAuthenticationType)
        } else {
            setOf(AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC)
        }
    }

    override fun newSignature(alias: String): Signature {
        val key = store().getKey(alias, null) as PrivateKey
        return Signature.getInstance(SHA256_WITH_ECDSA).apply { initSign(key) }
    }

    override fun aliases(): List<String> = store().aliases().toList()

    override fun delete(alias: String) {
        store().deleteEntry(alias)
    }

    /**
     * The level of a key made with [strongBoxRequested]. Android 12+ reports StrongBox itself and is believed; before that,
     * the Keystore can only say "secure hardware", which for a key that was asked for with `setIsStrongBoxBacked(true)`
     * (and so did NOT throw [StrongBoxUnavailableException]) must be StrongBox - nothing else could have accepted that
     * request. A key not asked for that way is taken as reported, so a later strict requirement check still refuses it.
     */
    private fun confirmedLevel(alias: String, strongBoxRequested: Boolean): AndroidKeystoreSigner.SecurityLevel {
        val reported = rawLevel(alias) ?: return AndroidKeystoreSigner.SecurityLevel.UNKNOWN
        return if (strongBoxRequested && Build.VERSION.SDK_INT < Build.VERSION_CODES.S && reported == AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT) {
            AndroidKeystoreSigner.SecurityLevel.STRONGBOX
        } else {
            reported
        }
    }

    /** What the Keystore reports for [alias] right now (StrongBox only distinguished from the TEE from Android 12). */
    private fun rawLevel(alias: String): AndroidKeystoreSigner.SecurityLevel? {
        val info = keyInfo(alias) ?: return null
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            AndroidKeystoreSigner.levelOf(info.securityLevel)
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT else AndroidKeystoreSigner.SecurityLevel.SOFTWARE
        }
    }

    private fun keyInfo(alias: String): KeyInfo? {
        val key = store().getKey(alias, null) as? PrivateKey ?: return null
        return runCatching { KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java) }.getOrNull()
    }

    private companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SHA256_WITH_ECDSA = "SHA256withECDSA"
    }
}
