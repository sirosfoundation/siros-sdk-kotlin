// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.math.BigInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.UUID
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.SignerSecurityProperties

/**
 * What [AndroidKeystoreSigner] needs from the platform, so the signer's logic is testable without a device. [SystemAndroidKeyStore]
 * is the real one (AndroidKeyStore provider).
 */
interface AndroidKeyStoreBackend {
    /** Thrown by [generate] when StrongBox was requested but this device has none (or cannot use it now). */
    class StrongBoxUnavailable(cause: Throwable? = null) : Exception("StrongBox is unavailable", cause)

    /** Generates an EC P-256 SIGN key for SHA-256, origin GENERATED (never imported), optionally bound to [attestationChallenge]. */
    fun generate(alias: String, attestationChallenge: ByteArray?, strongBox: Boolean)

    /** The certificate chain of [alias] as DER, leaf first (empty when the alias has none). */
    fun certificateChain(alias: String): List<ByteArray>

    fun publicKey(alias: String): ECPublicKey

    /** SHA256withECDSA, DER encoded (the platform's form). */
    fun signDer(alias: String, data: ByteArray): ByteArray

    fun aliases(): List<String>

    fun delete(alias: String)
}

/**
 * A [Signer] over the Android Keystore: EC P-256 keys that never leave the device's TEE or StrongBox.
 *
 * - [generateAttestedKey] binds a key to an attestation challenge (the wallet instance key's evidence, see the wallet's instance-key
 *   attestation) and asks for StrongBox first, falling back to the TEE when the device has none. One key per challenge: a retry
 *   after a failure uses a NEW key (a new alias) and a new challenge.
 * - [attestationChain] returns the chain as DER certificates, LEAF FIRST, in [AttestationChain.FORMAT_ANDROID_KEY]; null for a key
 *   that has none (fewer than two certificates).
 * - [sign] returns the JWS form (raw R||S, 64 bytes) of an ES256 signature.
 *
 * Origin is always GENERATED here: nothing is imported, which is part of what the backend verifies.
 */
class AndroidKeystoreSigner(
    private val backend: AndroidKeyStoreBackend,
    private val newAlias: () -> String = { ALIAS_PREFIX + UUID.randomUUID() },
    /** Which keys were generated into StrongBox in this process (key storage reporting only; the backend verifies the real level). */
    private val strongBoxAliases: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet(),
) : Signer {
    override val supportsAttestedKeyGeneration: Boolean get() = true

    override suspend fun generateKey(algorithm: String): String = withContext(Dispatchers.IO) { create(algorithm, null) }

    override suspend fun generateAttestedKey(algorithm: String, attestationChallenge: ByteArray): String {
        require(attestationChallenge.isNotEmpty()) { "an attestation challenge is required" }
        // Hardware key generation (StrongBox, attestation provisioning) can block for seconds: never on the caller's (main) dispatcher.
        return withContext(Dispatchers.IO) { create(algorithm, attestationChallenge) }
    }

    private fun create(algorithm: String, challenge: ByteArray?): String {
        require(algorithm == "ES256") { "AndroidKeystoreSigner supports ES256 only" }
        val alias = newAlias()
        try {
            backend.generate(alias, challenge, strongBox = true)
            strongBoxAliases += alias
        } catch (e: AndroidKeyStoreBackend.StrongBoxUnavailable) {
            // No StrongBox: the TEE, on a NEW alias (a half-made StrongBox key must not be reused).
            backend.delete(alias)
            val tee = newAlias()
            backend.generate(tee, challenge, strongBox = false)
            return tee
        }
        return alias
    }

    override suspend fun sign(keyId: String, data: ByteArray): ByteArray = withContext(Dispatchers.IO) { derToRaw(backend.signDer(keyId, data), 32) }

    override suspend fun listKeys(): List<SignerKeyInfo> = backend.aliases().filter { it.startsWith(ALIAS_PREFIX) }.map { SignerKeyInfo(it, "ES256") }

    override suspend fun deleteKey(keyId: String) {
        strongBoxAliases -= keyId
        backend.delete(keyId)
    }

    override suspend fun attestationChain(keyId: String): AttestationChain? {
        val chain = backend.certificateChain(keyId)
        return if (chain.size >= 2) AttestationChain(chain, ByteArray(0), AttestationChain.FORMAT_ANDROID_KEY) else null
    }

    override suspend fun exportPublicKey(keyId: String): ByteArray {
        val key = backend.publicKey(keyId)
        val b64 = Base64.getUrlEncoder().withoutPadding()
        fun coord(v: BigInteger): String = b64.encodeToString(v.toByteArray().let { raw -> ByteArray(32).also { out ->
            val src = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
            System.arraycopy(src, 0, out, 32 - src.size, src.size)
        } })
        return """{"kty":"EC","crv":"P-256","x":"${coord(key.w.affineX)}","y":"${coord(key.w.affineY)}"}""".toByteArray(Charsets.UTF_8)
    }

    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult = MigrationResult.ReEnrollmentRequired(keyId)

    override suspend fun securityProperties(keyId: String): SignerSecurityProperties =
        SignerSecurityProperties(
            keyStorage = listOf(if (keyId in strongBoxAliases) "hardware" else "trusted_execution"),
            userAuthentication = emptyList(),
            certification = CertificationInfo.None,
        )

    companion object {
        const val ALIAS_PREFIX = "siros-ak-"

        /** A DER ECDSA signature as the fixed-width R||S of a JWS (RFC 7515 appendix A.3). */
        internal fun derToRaw(der: ByteArray, size: Int): ByteArray {
            require(der.size > 8 && der[0] == 0x30.toByte()) { "not a DER ECDSA signature" }
            var i = 2
            if (der[1].toInt() and 0x80 != 0) i = 2 + (der[1].toInt() and 0x7f)
            fun readInt(): ByteArray {
                require(der[i] == 0x02.toByte()) { "not a DER ECDSA signature" }
                val len = der[i + 1].toInt() and 0xff
                val v = der.copyOfRange(i + 2, i + 2 + len)
                i += 2 + len
                val trimmed = v.dropWhile { it == 0.toByte() }.toByteArray()
                require(trimmed.size <= size) { "signature component too large" }
                return ByteArray(size).also { System.arraycopy(trimmed, 0, it, size - trimmed.size, trimmed.size) }
            }
            val r = readInt()
            val s = readInt()
            return r + s
        }
    }
}
