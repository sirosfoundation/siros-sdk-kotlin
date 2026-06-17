package org.sirosfoundation.sdk.keystore

import org.sirosfoundation.sdk.credentials.KeystoreException
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.security.SecureRandom
import java.util.Base64
import java.util.Date
import java.util.UUID
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * JWE-based keystore implementation fully compatible with the wallet-frontend
 * encrypted container format.
 *
 * Uses the same key hierarchy as the TypeScript web wallet:
 *   PRF output → HKDF(SHA-256, salt, info="eDiplomas PRF") → prfKey (AES-GCM-256)
 *   prfKey → unwrap ECDH private key → ECDH key agreement → AES-KW → unwrap mainKey
 *   mainKey → decrypt JWE (alg=A256GCMKW, enc=A256GCM) → WalletStateContainer
 *
 * This enables cross-device portability: the same encrypted private data
 * can be used by both the Android native wallet and the web wallet,
 * provided the same passkey PRF is used on the same authenticator.
 */
class JweKeystore(
    private val json: Json = Json { ignoreUnknownKeys = true },
) : KeystoreManager {

    private val mutex = Mutex()
    private var keys: MutableMap<String, ECKey> = mutableMapOf()
    private var credentials: MutableMap<String, String> = mutableMapOf()
    @Volatile private var mainKey: SecretKey? = null
    @Volatile private var containerMetadata: ContainerData? = null

    override val isUnlocked: Boolean get() = mainKey != null

    override suspend fun unlock(
        prfOutput: ByteArray,
        encryptedContainer: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) = mutex.withLock {
        if (encryptedContainer.isNotEmpty()) {
            // Parse the full container format from the wallet-frontend
            val container = EncryptedContainer.parse(encryptedContainer)
            val mainKeyInfo = container.mainKey
                ?: throw KeystoreException("Container missing mainKey")

            // Find the matching PRF key entry (use the provided hkdfSalt to match)
            val prfKeyInfo = container.prfKeys.firstOrNull { it.hkdfSalt.contentEquals(hkdfSalt) }
                ?: container.prfKeys.firstOrNull()
                ?: throw KeystoreException("No PRF key entries in container")

            // Derive the PRF wrapping key: HKDF(PRF output, salt, info)
            val prfKey = EncryptedContainer.derivePrfKey(prfOutput, prfKeyInfo.hkdfSalt, prfKeyInfo.hkdfInfo)

            // Unwrap the main key through ECDH encapsulation
            val unwrappedMainKey = EncryptedContainer.unwrapMainKey(prfKey, prfKeyInfo, mainKeyInfo)
            mainKey = unwrappedMainKey

            // Decrypt the JWE using the main key (A256GCMKW / A256GCM)
            val jweObject = JWEObject.parse(container.jwe)
            jweObject.decrypt(AESDecrypter(unwrappedMainKey))

            // Parse the WalletStateContainer plaintext
            val plaintextJson = json.parseToJsonElement(jweObject.payload.toString())
            loadWalletState(plaintextJson)

            // Preserve container metadata for re-export
            containerMetadata = container
        } else {
            // First-time setup: generate a fresh main key and container structure
            val (newMainKey, newMainKeyInfo) = EncryptedContainer.generateMainKey()
            mainKey = newMainKey

            // Build a PRF key entry for this authenticator
            val prfKey = EncryptedContainer.derivePrfKey(prfOutput, hkdfSalt, hkdfInfo)
            val encapsulation = EncryptedContainer.wrapMainKey(prfKey, newMainKey, newMainKeyInfo)

            containerMetadata = ContainerData(
                jwe = "", // will be set on export
                mainKey = newMainKeyInfo,
                prfKeys = listOf(
                    PrfKeyInfo(
                        credentialId = ByteArray(0), // will be set by SirosWallet
                        transports = null,
                        prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) },
                        hkdfSalt = hkdfSalt,
                        hkdfInfo = hkdfInfo,
                        algorithm = AesGcmKeyAlgorithm("AES-GCM", 256),
                        keypair = encapsulation.keypair,
                        unwrapKey = encapsulation.unwrapKey,
                    )
                ),
            )
        }

        Timber.i("Keystore unlocked with ${keys.size} keys, ${credentials.size} credentials")
    }

    /**
     * Set the credential ID on the PRF key entry (called after registration
     * when the credential ID is known).
     */
    fun setCredentialId(credentialId: ByteArray) {
        val meta = containerMetadata ?: return
        if (meta.prfKeys.isNotEmpty() && meta.prfKeys[0].credentialId.isEmpty()) {
            containerMetadata = meta.copy(
                prfKeys = listOf(meta.prfKeys[0].copy(credentialId = credentialId)) + meta.prfKeys.drop(1)
            )
        }
    }

    private fun loadWalletState(element: kotlinx.serialization.json.JsonElement) {
        val obj = element as? kotlinx.serialization.json.JsonObject ?: return

        // Parse V3 WalletStateContainer: { events: [...], S: { keypairs, credentials, ... }, lastEventHash }
        val state = obj["S"]?.let { it as? kotlinx.serialization.json.JsonObject }
        if (state != null) {
            // V3 format: keypairs and credentials are in the "S" field
            loadFromWalletStateV3(state)
        } else if (obj.containsKey("keys")) {
            // Legacy Kotlin-only format: { keys: [...], credentials: {...} }
            val legacyState = json.decodeFromString(KeystoreState.serializer(), element.toString())
            keys = legacyState.keys.associate { stored ->
                val ecKey = ECKey.parse(stored.jwk)
                stored.keyId to ecKey
            }.toMutableMap()
            credentials = legacyState.credentials.toMutableMap()
        }
    }

    private fun loadFromWalletStateV3(state: kotlinx.serialization.json.JsonObject) {
        // Parse keypairs: [{ kid, keypair: { kid, did, alg, publicKey, privateKey } }]
        val keypairsArray = state["keypairs"]
        if (keypairsArray is kotlinx.serialization.json.JsonArray) {
            for (entry in keypairsArray) {
                val entryObj = entry as? kotlinx.serialization.json.JsonObject ?: continue
                val keypairObj = entryObj["keypair"] as? kotlinx.serialization.json.JsonObject ?: continue
                val kid = keypairObj["kid"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content } ?: continue
                val privateKeyJwk = keypairObj["privateKey"] as? kotlinx.serialization.json.JsonObject ?: continue

                try {
                    val ecKey = ECKey.parse(privateKeyJwk.toString())
                    keys[kid] = ecKey
                } catch (e: Exception) {
                    Timber.w(e, "Failed to parse keypair $kid")
                }
            }
        }

        // Parse credentials: [{ credentialId, format, data, kid, ... }]
        val credsArray = state["credentials"]
        if (credsArray is kotlinx.serialization.json.JsonArray) {
            for (entry in credsArray) {
                val credObj = entry as? kotlinx.serialization.json.JsonObject ?: continue
                val credId = credObj["credentialId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    ?: continue
                val data = credObj["data"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    ?: continue
                credentials[credId] = data
            }
        }
    }

    override fun lock() {
        keys.clear()
        credentials.clear()
        mainKey = null
        containerMetadata = null
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

    override suspend fun signVpToken(
        credential: String,
        disclosedClaims: List<String>?,
        nonce: String,
        audience: String,
    ): String = mutex.withLock {
        requireUnlocked()
        val key = keys.values.firstOrNull()
            ?: run {
                Timber.i("No keys available, generating a new key for VP signing")
                val keyId = UUID.randomUUID().toString()
                val ecKey = ECKeyGenerator(Curve.P_256).keyID(keyId).generate()
                keys[keyId] = ecKey
                ecKey
            }

        // Split the SD-JWT into parts: IssuerJWT~disclosure1~disclosure2~...~
        val parts = credential.split("~")
        val issuerJwt = parts[0]
        val disclosures = parts.drop(1).filter { it.isNotEmpty() }

        // Filter disclosures if specific claims are requested
        val selectedDisclosures = if (disclosedClaims.isNullOrEmpty()) {
            disclosures
        } else {
            filterDisclosures(disclosures, disclosedClaims)
        }

        // Build the SD-JWT presentation string (with trailing ~)
        val sdJwtPresentation = buildString {
            append(issuerJwt)
            for (d in selectedDisclosures) {
                append("~")
                append(d)
            }
            append("~")
        }

        // Compute sd_hash = base64url(SHA-256(sdJwtPresentation))
        val sdHashBytes = java.security.MessageDigest.getInstance("SHA-256")
            .digest(sdJwtPresentation.toByteArray(Charsets.US_ASCII))
        val sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(sdHashBytes)

        // Build KB-JWT with typ: "kb+jwt", alg: "ES256", jwk: <public key>
        // Per RFC 9901 + real-world interop: jwk MUST be in header, d MUST be stripped
        val publicJwk = key.toPublicJWK()
        val kbHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(com.nimbusds.jose.JOSEObjectType("kb+jwt"))
            .jwk(publicJwk)
            .build()

        val kbClaims = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date())
            .claim("nonce", nonce)
            .claim("sd_hash", sdHash)
            .build()

        val kbJwt = SignedJWT(kbHeader, kbClaims)
        kbJwt.sign(ECDSASigner(key))

        // Assemble: sdJwtPresentation + KB-JWT (no separator — presentation already ends with ~)
        sdJwtPresentation + kbJwt.serialize()
    }

    /**
     * Filter SD-JWT disclosures to only those matching the requested claim names.
     *
     * Each disclosure is a base64url-encoded JSON array: ["salt", "claim_name", "value"].
     * We decode each, extract the claim name (index 1), and keep only those in [claimNames].
     */
    private fun filterDisclosures(disclosures: List<String>, claimNames: List<String>): List<String> {
        val requested = claimNames.toSet()
        return disclosures.filter { disclosure ->
            try {
                val decoded = Base64.getUrlDecoder().decode(disclosure)
                val arr = json.parseToJsonElement(String(decoded, Charsets.UTF_8))
                val claimName = arr.jsonArray.getOrNull(1)?.jsonPrimitive?.contentOrNull
                claimName != null && claimName in requested
            } catch (e: Exception) {
                // If we can't parse a disclosure, include it to be safe
                Timber.w(e, "Could not parse SD-JWT disclosure, including it")
                true
            }
        }
    }

    override suspend fun exportEncryptedContainer(): ByteArray = mutex.withLock {
        requireUnlocked()
        val currentMainKey = mainKey!!

        // Build the WalletStateContainer V3 plaintext
        val walletState = buildWalletStateV3()
        val payload = json.encodeToString(
            kotlinx.serialization.json.JsonObject.serializer(),
            walletState
        )

        // Encrypt the JWE with A256GCMKW / A256GCM using the main key
        val header = JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM)
        val jweObject = JWEObject(header, Payload(payload))
        jweObject.encrypt(AESEncrypter(currentMainKey))
        val jweString = jweObject.serialize()

        // Build the full container with the updated JWE
        val meta = containerMetadata ?: throw KeystoreException("No container metadata")
        val updatedContainer = meta.copy(jwe = jweString)
        containerMetadata = updatedContainer

        EncryptedContainer.serialize(updatedContainer)
    }

    private fun buildWalletStateV3(): kotlinx.serialization.json.JsonObject {
        return kotlinx.serialization.json.buildJsonObject {
            put("lastEventHash", kotlinx.serialization.json.JsonPrimitive(""))
            put("events", kotlinx.serialization.json.JsonArray(emptyList()))
            put("S", kotlinx.serialization.json.buildJsonObject {
                put("schemaVersion", kotlinx.serialization.json.JsonPrimitive(3))
                put("keypairs", kotlinx.serialization.json.JsonArray(
                    keys.map { (kid, ecKey) ->
                        kotlinx.serialization.json.buildJsonObject {
                            put("kid", kotlinx.serialization.json.JsonPrimitive(kid))
                            put("keypair", kotlinx.serialization.json.buildJsonObject {
                                put("kid", kotlinx.serialization.json.JsonPrimitive(kid))
                                put("did", kotlinx.serialization.json.JsonPrimitive(""))
                                put("alg", kotlinx.serialization.json.JsonPrimitive("ES256"))
                                // Export public key as JWK
                                val pubJwk = json.parseToJsonElement(ecKey.toPublicJWK().toJSONString())
                                put("publicKey", pubJwk)
                                // Export private key as JWK (inside the encrypted JWE)
                                val privJwk = json.parseToJsonElement(ecKey.toJSONString())
                                put("privateKey", privJwk)
                            })
                        }
                    }
                ))
                put("credentials", kotlinx.serialization.json.JsonArray(
                    credentials.map { (id, data) ->
                        kotlinx.serialization.json.buildJsonObject {
                            put("credentialId", kotlinx.serialization.json.JsonPrimitive(id))
                            put("format", kotlinx.serialization.json.JsonPrimitive(""))
                            put("data", kotlinx.serialization.json.JsonPrimitive(data))
                            put("kid", kotlinx.serialization.json.JsonPrimitive(""))
                            put("instanceId", kotlinx.serialization.json.JsonPrimitive(0))
                            put("batchId", kotlinx.serialization.json.JsonPrimitive(0))
                            put("credentialIssuerIdentifier", kotlinx.serialization.json.JsonPrimitive(""))
                            put("credentialConfigurationId", kotlinx.serialization.json.JsonPrimitive(""))
                        }
                    }
                ))
                put("presentations", kotlinx.serialization.json.JsonArray(emptyList()))
                put("settings", kotlinx.serialization.json.buildJsonObject {
                    put("openidRefreshTokenMaxAgeInSeconds", kotlinx.serialization.json.JsonPrimitive(""))
                })
                put("credentialIssuanceSessions", kotlinx.serialization.json.JsonArray(emptyList()))
            })
        }
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

    override suspend fun generateKeypairs(count: Int): List<KeypairInfo> = mutex.withLock {
        requireUnlocked()
        (1..count).map {
            val keyId = UUID.randomUUID().toString()
            val ecKey = ECKeyGenerator(Curve.P_256)
                .keyID(keyId)
                .generate()
            keys[keyId] = ecKey
            val pubJwk = kotlinx.serialization.json.Json.parseToJsonElement(
                ecKey.toPublicJWK().toJSONString()
            ) as kotlinx.serialization.json.JsonObject
            KeypairInfo(keyId = keyId, publicKeyJWK = pubJwk)
        }
    }

    private fun requireUnlocked() {
        if (!isUnlocked) throw KeystoreException("Keystore is locked")
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
