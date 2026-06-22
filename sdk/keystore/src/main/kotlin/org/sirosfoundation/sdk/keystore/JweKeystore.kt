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
import java.security.MessageDigest
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
    // Preserve full WalletStateContainer for round-trip fidelity
    private var preservedWalletState: kotlinx.serialization.json.JsonObject? = null

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

            // Find the matching PRF key entry by credentialId (passed via wallet layer)
            // Fallback to first entry only if no credentialId match (legacy compat)
            val prfKeyInfo = container.prfKeys.firstOrNull { it.credentialId.isNotEmpty() && it.hkdfSalt.contentEquals(hkdfSalt) }
                ?: container.prfKeys.firstOrNull { it.hkdfSalt.contentEquals(hkdfSalt) }
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

            // Parse the WalletStateContainer plaintext and preserve for round-trip
            val plaintextJson = json.parseToJsonElement(jweObject.payload.toString())
            if (plaintextJson is kotlinx.serialization.json.JsonObject) {
                preservedWalletState = plaintextJson
            }
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
                    // Ensure the key has the correct kid set
                    val keyWithId = ECKey.Builder(ecKey).keyID(kid).build()
                    keys[kid] = keyWithId
                } catch (e: Exception) {
                    Timber.w(e, "Failed to parse keypair $kid")
                }
            }
        }

        // Parse credentials: [{ credentialId, format, data, kid, ... }]
        // Store as serialized StoredCredential to preserve kid binding and format.
        val credsArray = state["credentials"]
        if (credsArray is kotlinx.serialization.json.JsonArray) {
            for (entry in credsArray) {
                val credObj = entry as? kotlinx.serialization.json.JsonObject ?: continue
                val credId = credObj["credentialId"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    ?: continue
                val data = credObj["data"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                    ?: continue
                val credKid = credObj["kid"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                val credFormat = credObj["format"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""

                // Store as serialized StoredCredential JSON to preserve metadata
                val storedJson = kotlinx.serialization.json.buildJsonObject {
                    put("id", kotlinx.serialization.json.JsonPrimitive(credId))
                    put("format", kotlinx.serialization.json.JsonPrimitive(credFormat))
                    put("raw", kotlinx.serialization.json.JsonPrimitive(data))
                    if (!credKid.isNullOrEmpty()) {
                        put("kid", kotlinx.serialization.json.JsonPrimitive(credKid))
                    }
                }
                credentials[credId] = storedJson.toString()
            }
        }
    }

    override fun lock() {
        keys.clear()
        credentials.clear()
        mainKey = null
        containerMetadata = null
        preservedWalletState = null
        Timber.i("Keystore locked")
    }

    override suspend fun generateKey(algorithm: String): String = mutex.withLock {
        requireUnlocked()
        val ecKey = ECKeyGenerator(Curve.P_256).generate()
        val keyId = ecKey.computeThumbprint().toString()
        val keyWithId = ECKey.Builder(ecKey).keyID(keyId).build()
        keys[keyId] = keyWithId
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
                val ecKey = ECKeyGenerator(Curve.P_256).generate()
                val keyId = ecKey.computeThumbprint().toString()
                val keyWithId = ECKey.Builder(ecKey).keyID(keyId).build()
                keys[keyId] = keyWithId
                keyWithId
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
                val ecKey = ECKeyGenerator(Curve.P_256).generate()
                val keyId = ecKey.computeThumbprint().toString()
                val keyWithId = ECKey.Builder(ecKey).keyID(keyId).build()
                keys[keyId] = keyWithId
                keyWithId
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
                val ecKey = ECKeyGenerator(Curve.P_256).generate()
                val keyId = ecKey.computeThumbprint().toString()
                val keyWithId = ECKey.Builder(ecKey).keyID(keyId).build()
                keys[keyId] = keyWithId
                keyWithId
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
        // Preserve existing state if available, otherwise initialize fresh
        val existingState = preservedWalletState
        if (existingState != null) {
            // Round-trip: preserve exact structure from loaded state
            return existingState
        }
        // First-time or missing state: build minimal valid state
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
                                // Preserve DID from original state if available; only compute for fresh keys
                                val preservedDid = existingState?.let { state ->
                                    (state["S"] as? kotlinx.serialization.json.JsonObject)?.let { s ->
                                        (s["keypairs"] as? kotlinx.serialization.json.JsonArray)?.find { entry ->
                                            (entry as? kotlinx.serialization.json.JsonObject)?.let { e ->
                                                ((e["keypair"] as? kotlinx.serialization.json.JsonObject)?.get("kid") as? kotlinx.serialization.json.JsonPrimitive)?.content == kid
                                            } ?: false
                                        }?.let { matchedEntry ->
                                            (matchedEntry as? kotlinx.serialization.json.JsonObject)?.let { e ->
                                                ((e["keypair"] as? kotlinx.serialization.json.JsonObject)?.get("did") as? kotlinx.serialization.json.JsonPrimitive)?.content
                                            }
                                        }
                                    }
                                }
                                put("did", kotlinx.serialization.json.JsonPrimitive(preservedDid ?: computeDidKey(ecKey)))
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
                        // Parse StoredCredential to extract metadata
                        val parsed = try {
                            json.parseToJsonElement(data) as? kotlinx.serialization.json.JsonObject
                        } catch (_: Exception) { null }
                        
                        // Try to find and preserve original credential entry from preserved state
                        val originalCred = existingState?.let { state ->
                            (state["S"] as? kotlinx.serialization.json.JsonObject)?.let { s ->
                                (s["credentials"] as? kotlinx.serialization.json.JsonArray)?.find { entry ->
                                    (entry as? kotlinx.serialization.json.JsonObject)?.let { e ->
                                        ((e["credentialId"] as? kotlinx.serialization.json.JsonPrimitive)?.content == id)
                                    } ?: false
                                }
                            }
                        } as? kotlinx.serialization.json.JsonObject
                        
                        // Preserve all metadata fields from original; use stored/parsed values as fallback
                        val credKid = originalCred?.get("kid")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("kid")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
                        val credFormat = originalCred?.get("format")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("format")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: ""
                        val credData = originalCred?.get("data")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: parsed?.get("raw")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull } ?: data
                        val instanceId = originalCred?.get("instanceId")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                            ?: "0"
                        val batchId = originalCred?.get("batchId")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                            ?: "0"
                        val issuerIdent = originalCred?.get("credentialIssuerIdentifier")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: ""
                        val configId = originalCred?.get("credentialConfigurationId")?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                            ?: ""
                        
                        kotlinx.serialization.json.buildJsonObject {
                            put("credentialId", kotlinx.serialization.json.JsonPrimitive(id))
                            put("format", kotlinx.serialization.json.JsonPrimitive(credFormat))
                            put("data", kotlinx.serialization.json.JsonPrimitive(credData))
                            put("kid", kotlinx.serialization.json.JsonPrimitive(credKid))
                            put("instanceId", kotlinx.serialization.json.JsonPrimitive(instanceId))
                            put("batchId", kotlinx.serialization.json.JsonPrimitive(batchId))
                            put("credentialIssuerIdentifier", kotlinx.serialization.json.JsonPrimitive(issuerIdent))
                            put("credentialConfigurationId", kotlinx.serialization.json.JsonPrimitive(configId))
                        }
                    }
                ))
                // Preserve presentations and issuance sessions from original state if present
                val presentations = existingState?.let { state ->
                    (state["S"] as? kotlinx.serialization.json.JsonObject)?.get("presentations")
                        ?: kotlinx.serialization.json.JsonArray(emptyList())
                } ?: kotlinx.serialization.json.JsonArray(emptyList())
                put("presentations", presentations)
                
                put("settings", kotlinx.serialization.json.buildJsonObject {
                    // Preserve settings from original state; use "0" as normative default for new state
                    val refreshTokenAge = existingState?.let { state ->
                        (state["S"] as? kotlinx.serialization.json.JsonObject)?.get("settings")?.let { s ->
                            (s as? kotlinx.serialization.json.JsonObject)?.get("openidRefreshTokenMaxAgeInSeconds")
                                ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
                        }
                    } ?: "0"
                    put("openidRefreshTokenMaxAgeInSeconds", kotlinx.serialization.json.JsonPrimitive(refreshTokenAge))
                })
                
                val credIssuanceSessions = existingState?.let { state ->
                    (state["S"] as? kotlinx.serialization.json.JsonObject)?.get("credentialIssuanceSessions")
                        ?: kotlinx.serialization.json.JsonArray(emptyList())
                } ?: kotlinx.serialization.json.JsonArray(emptyList())
                put("credentialIssuanceSessions", credIssuanceSessions)
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
        require(count >= 1) { "count must be >= 1" }
        (1..count).map {
            val ecKey = ECKeyGenerator(Curve.P_256).generate()
            val keyId = ecKey.computeThumbprint().toString()
            val keyWithId = ECKey.Builder(ecKey).keyID(keyId).build()
            keys[keyId] = keyWithId
            val pubJwk = kotlinx.serialization.json.Json.parseToJsonElement(
                keyWithId.toPublicJWK().toJSONString()
            ) as kotlinx.serialization.json.JsonObject
            KeypairInfo(keyId = keyId, publicKeyJWK = pubJwk)
        }
    }

    private fun requireUnlocked() {
        if (!isUnlocked) throw KeystoreException("Keystore is locked")
    }

    /**
     * Compute the did:key identifier for a P-256 EC key.
     * Format: did:key:zDn... (Multicodec 0x1200 for P-256 public key, base58btc).
     */
    private fun computeDidKey(ecKey: ECKey): String {
        val pub = ecKey.toECPublicKey()
        // Compressed point: 0x02/0x03 prefix + 32-byte x coordinate
        val xBytes = unsignedBigIntBytes(pub.w.affineX, 32)
        val prefix: Byte = if (pub.w.affineY.testBit(0)) 0x03 else 0x02
        val compressed = byteArrayOf(prefix) + xBytes
        // Multicodec varint for P-256 public key: 0x80, 0x24
        val multicodec = byteArrayOf(0x80.toByte(), 0x24) + compressed
        return "did:key:z${base58Btc(multicodec)}"
    }

    /** Convert BigInteger to fixed-size unsigned byte array (big-endian, zero-padded). */
    private fun unsignedBigIntBytes(value: java.math.BigInteger, size: Int): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == size -> bytes
            bytes.size > size -> bytes.copyOfRange(bytes.size - size, bytes.size)
            else -> ByteArray(size - bytes.size) + bytes
        }
    }

    /** Base58 Bitcoin encoding (no checksum). */
    private fun base58Btc(input: ByteArray): String {
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bi = java.math.BigInteger(1, input)
        val sb = StringBuilder()
        val base = java.math.BigInteger.valueOf(58)
        while (bi > java.math.BigInteger.ZERO) {
            val (quotient, remainder) = bi.divideAndRemainder(base)
            sb.append(alphabet[remainder.toInt()])
            bi = quotient
        }
        // Preserve leading zeros
        for (b in input) {
            if (b.toInt() == 0) sb.append('1') else break
        }
        return sb.reverse().toString()
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
