package org.sirosfoundation.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.util.Date
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * JWE-based keystore implementation compatible with the wallet-frontend
 * encrypted container format.
 *
 * Keys are stored as JWK objects inside a JWE envelope encrypted with
 * an AES-256-GCM key derived from the WebAuthn PRF output via HKDF-SHA256.
 *
 * Key derivation matches the web frontend:
 *   PRF output → HKDF(hash=SHA-256, salt=hkdfSalt, info=hkdfInfo) → 256-bit AES key
 */
class JweKeystore(
    private val json: Json = Json { ignoreUnknownKeys = true },
) : KeystoreManager {

    private val mutex = Mutex()
    private var keys: MutableMap<String, ECKey> = mutableMapOf()
    private var credentials: MutableMap<String, String> = mutableMapOf()
    @Volatile private var encryptionKey: ByteArray? = null

    override val isUnlocked: Boolean get() = encryptionKey != null

    override suspend fun unlock(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) = mutex.withLock {
        val derivedKey = hkdfSha256(prfOutput, hkdfSalt, hkdfInfo, 32)
        encryptionKey = derivedKey

        if (encryptedContainer.isNotEmpty()) {
            val jweString = encryptedContainer.toString(Charsets.UTF_8)
            val jweObject = JWEObject.parse(jweString)
            val secretKey = SecretKeySpec(derivedKey, "AES")
            jweObject.decrypt(DirectDecrypter(secretKey))

            val state = json.decodeFromString(
                KeystoreState.serializer(),
                jweObject.payload.toString()
            )
            keys = state.keys.associate { stored ->
                val ecKey = ECKey.parse(stored.jwk)
                stored.keyId to ecKey
            }.toMutableMap()
            credentials = state.credentials.toMutableMap()
        }

        Timber.i("Keystore unlocked with ${keys.size} keys, ${credentials.size} credentials")
    }

    override fun lock() {
        // lock() is non-suspend — use tryLock as best-effort
        keys.clear()
        credentials.clear()
        encryptionKey?.fill(0)
        encryptionKey = null
        Timber.i("Keystore locked")
    }

    override suspend fun generateKey(algorithm: String): String = mutex.withLock {
        requireUnlocked()
        val keyId = UUID.randomUUID().toString()
        val ecKey = ECKeyGenerator(Curve.P_256)
            .keyID(keyId)
            .generate()
        keys[keyId] = ecKey
        Timber.d("Generated key: $keyId")
        keyId
    }

    override suspend fun sign(keyId: String, payload: ByteArray, algorithm: String): ByteArray = mutex.withLock {
        requireUnlocked()
        val key = keys[keyId] ?: throw KeystoreException("Key not found: $keyId")
        val signer = ECDSASigner(key)
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build()
        val jwsObject = com.nimbusds.jose.JWSObject(header, Payload(payload))
        jwsObject.sign(signer)
        jwsObject.serialize().toByteArray(Charsets.UTF_8)
    }

    override suspend fun generateProof(audience: String, nonce: String): String = mutex.withLock {
        requireUnlocked()
        val key = keys.values.firstOrNull()
            ?: run {
                Timber.i("No keys available, generating a new key for proof")
                val keyId = UUID.randomUUID().toString()
                val ecKey = ECKeyGenerator(Curve.P_256).keyID(keyId).generate()
                keys[keyId] = ecKey
                ecKey
            }

        Timber.d("generateProof: building claims for audience=$audience")
        val claims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(key.keyID)
            .type(com.nimbusds.jose.JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(key.toPublicJWK())
            .build()

        Timber.d("generateProof: signing JWT with key ${key.keyID}")
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key))
        Timber.d("generateProof: JWT signed successfully")
        jwt.serialize()
    }

    override suspend fun signPresentation(nonce: String, audience: String, credentialIds: List<String>): String = mutex.withLock {
        requireUnlocked()
        val key = keys.values.firstOrNull()
            ?: run {
                Timber.i("No keys available, generating a new key for VP signing")
                val keyId = UUID.randomUUID().toString()
                val ecKey = ECKeyGenerator(Curve.P_256).keyID(keyId).generate()
                keys[keyId] = ecKey
                ecKey
            }

        val claims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .jwtID(UUID.randomUUID().toString())
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(key.keyID)
            .build()

        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key))
        jwt.serialize()
    }

    override suspend fun exportEncryptedContainer(): ByteArray = mutex.withLock {
        requireUnlocked()
        val state = KeystoreState(
            keys = keys.map { (id, key) ->
                StoredKey(keyId = id, jwk = key.toJSONString(), algorithm = "ES256", createdAt = System.currentTimeMillis())
            },
            credentials = credentials.toMap(),
        )
        val payload = json.encodeToString(KeystoreState.serializer(), state)
        val header = JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
        val jweObject = JWEObject(header, Payload(payload))
        val secretKey = SecretKeySpec(encryptionKey!!, "AES")
        jweObject.encrypt(DirectEncrypter(secretKey))
        jweObject.serialize().toByteArray(Charsets.UTF_8)
    }

    override fun listKeys(): List<KeyInfo> {
        return keys.map { (id, _) ->
            KeyInfo(keyId = id, algorithm = "ES256", createdAt = 0)
        }
    }

    // ── Credential storage ──────────────────────────────────────────

    override suspend fun saveCredential(id: String, json: String) = mutex.withLock {
        requireUnlocked()
        credentials[id] = json
    }

    override suspend fun getCredential(id: String): String? = mutex.withLock {
        requireUnlocked()
        credentials[id]
    }

    override suspend fun getAllCredentials(): Map<String, String> = mutex.withLock {
        requireUnlocked()
        credentials.toMap()
    }

    override suspend fun deleteCredential(id: String): Unit = mutex.withLock {
        requireUnlocked()
        credentials.remove(id)
        Unit
    }

    override suspend fun clearCredentials(): Unit = mutex.withLock {
        requireUnlocked()
        credentials.clear()
    }

    private fun requireUnlocked() {
        if (!isUnlocked) throw KeystoreException("Keystore is locked")
    }

    /**
     * HKDF-SHA256: extract + expand.
     *
     * Matches the web frontend's key derivation:
     *   HKDF(hash=SHA-256, ikm=prfOutput, salt=hkdfSalt, info=hkdfInfo) → outputLen bytes
     */
    private fun hkdfSha256(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLen: Int,
    ): ByteArray {
        // Extract: PRK = HMAC-SHA256(salt, ikm)
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)

        // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
        // For 32-byte output, a single block is sufficient.
        require(outputLen <= 32) { "HKDF output length must be <= 32 for single-block expand" }
        val expandInput = ByteArray(info.size + 1)
        System.arraycopy(info, 0, expandInput, 0, info.size)
        expandInput[info.size] = 0x01
        val okm = hmacSha256(prk, expandInput)
        return okm.copyOf(outputLen)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    @Serializable
    private data class KeystoreState(
        val keys: List<StoredKey>,
        val credentials: Map<String, String> = emptyMap(),
    )

    @Serializable
    private data class StoredKey(
        val keyId: String,
        val jwk: String,
        val algorithm: String,
        val createdAt: Long,
    )
}

class KeystoreException(message: String, cause: Throwable? = null) : Exception(message, cause)
