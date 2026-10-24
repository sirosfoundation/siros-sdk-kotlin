// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** The real [AndroidKeyStoreBackend]: the `AndroidKeyStore` provider. Needs a device (or emulator); see the instrumented tests. */
class SystemAndroidKeyStore : AndroidKeyStoreBackend {
    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun generate(alias: String, attestationChallenge: ByteArray?, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (attestationChallenge != null) builder.setAttestationChallenge(attestationChallenge)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(builder.build()) }
                .generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            throw AndroidKeyStoreBackend.StrongBoxUnavailable(e)
        }
    }

    override fun certificateChain(alias: String): List<ByteArray> =
        store().getCertificateChain(alias)?.map { it.encoded }.orEmpty()

    override fun publicKey(alias: String): ECPublicKey = store().getCertificate(alias).publicKey as ECPublicKey

    override fun signDer(alias: String, data: ByteArray): ByteArray {
        val key = store().getKey(alias, null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(data)
            sign()
        }
    }

    override fun aliases(): List<String> = store().aliases().toList()

    override fun delete(alias: String) {
        store().deleteEntry(alias)
    }
}
