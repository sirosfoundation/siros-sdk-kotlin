package org.siros.sdk.keystore

import org.siros.sdk.credentials.KeystoreException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Kotlin model of the wallet-frontend's `EncryptedContainer` format.
 *
 * This enables cross-platform interoperability: the same encrypted
 * private data can be decrypted by both the Kotlin Android SDK and
 * the TypeScript web wallet, provided the same passkey PRF is used.
 *
 * Container structure:
 * ```json
 * {
 *   "mainKey": { "publicKey": {...}, "unwrapKey": {...} },
 *   "prfKeys": [ { "credentialId": {"$b64u": "..."}, ... } ],
 *   "jwe": "eyJ..."
 * }
 * ```
 */
object EncryptedContainer {

    private val b64Url = Base64.getUrlEncoder().withoutPadding()
    private val b64UrlDecoder = Base64.getUrlDecoder()
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Parse a serialized encrypted container from the backend.
     * Handles both tagged binary format (`{"$b64u": "..."}`) and plain JSON.
     */
    fun parse(data: ByteArray): ContainerData {
        val text = data.toString(Charsets.UTF_8).trim()
        val root = json.parseToJsonElement(text).jsonObject
        return parseContainer(root)
    }

    /**
     * Serialize a container to the format expected by the backend.
     * Binary fields are encoded as `{"$b64u": "base64url"}`.
     */
    fun serialize(container: ContainerData): ByteArray {
        val obj = serializeContainer(container)
        return json.encodeToString(JsonObject.serializer(), obj).toByteArray(Charsets.UTF_8)
    }

    // ── Crypto operations ───────────────────────────────────────────

    /**
     * Derive the PRF wrapping key using HKDF-SHA256, matching the
     * wallet-frontend's `derivePrfKey()`.
     *
     * @param prfOutput raw PRF output from WebAuthn (32 bytes)
     * @param hkdfSalt  32-byte random salt stored per PRF key
     * @param hkdfInfo  info string (typically "eDiplomas PRF" encoded as UTF-8)
     * @return AES-256-GCM key for wrapping/unwrapping
     */
    fun derivePrfKey(prfOutput: ByteArray, hkdfSalt: ByteArray, hkdfInfo: ByteArray): SecretKey {
        val derived = hkdfSha256(prfOutput, hkdfSalt, hkdfInfo, 32)
        return SecretKeySpec(derived, "AES")
    }

    /**
     * Unwrap the main encryption key from a V2 PRF key entry using ECDH
     * key encapsulation, matching the wallet-frontend's `decapsulateKey()`.
     *
     * Flow: prfKey → unwrap ECDH private key → ECDH(private, mainKey.publicKey)
     *       → AES-KW unwrap → mainKey
     */
    fun unwrapMainKey(
        prfKey: SecretKey,
        prfKeyInfo: PrfKeyInfo,
        mainKeyInfo: MainKeyInfo,
    ): SecretKey {
        // Step 1: Unwrap the ECDH private key using AES-GCM with the PRF-derived key
        val ecdhPrivateKey = unwrapEcdhPrivateKey(prfKey, prfKeyInfo.keypair.privateKey)

        // Step 2: Import the mainKey's ephemeral public key
        val ecdhPublicKey = importEcPublicKey(mainKeyInfo.publicKey.importKey.keyData)

        // Step 3: ECDH key agreement → AES-KW wrapping key
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(ecdhPrivateKey)
        keyAgreement.doPhase(ecdhPublicKey, true)
        val sharedSecret = keyAgreement.generateSecret()

        // The shared secret is used directly as AES-KW key (256 bits)
        // WebCrypto deriveKey with AES-KW uses raw ECDH output truncated/expanded to key length
        val aesKwKey = SecretKeySpec(sharedSecret.copyOf(32), "AES")

        // Step 4: AES-KW unwrap the main key
        val unwrapCipher = Cipher.getInstance("AESWrap")
        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKwKey)
        return unwrapCipher.unwrap(
            prfKeyInfo.unwrapKey.wrappedKey, "AES", Cipher.SECRET_KEY
        ) as SecretKey
    }

    /**
     * Wrap a main key for a PRF key entry using ECDH key encapsulation.
     * Produces the keypair + unwrapKey structure matching the frontend's `encapsulateKey()`.
     */
    fun wrapMainKey(
        prfKey: SecretKey,
        mainKey: SecretKey,
        mainKeyInfo: MainKeyInfo,
    ): PrfKeyEncapsulation {
        // Step 1: Generate a fresh ECDH keypair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val ecdhKeypair = kpg.generateKeyPair()
        val ecdhPublicKey = ecdhKeypair.public as ECPublicKey
        val ecdhPrivateKey = ecdhKeypair.private as ECPrivateKey

        // Step 2: Export public key in uncompressed format
        val publicKeyBytes = exportEcPublicKey(ecdhPublicKey)

        // Step 3: Wrap the ECDH private key with the PRF key using AES-GCM
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val privateKeyJwk = exportEcPrivateKeyJwk(ecdhPrivateKey, ecdhPublicKey)
        val wrappedPrivateKey = aesGcmEncrypt(prfKey, iv, privateKeyJwk)

        // Step 4: ECDH agreement with mainKey's public key → AES-KW
        val mainPublicKey = importEcPublicKey(mainKeyInfo.publicKey.importKey.keyData)
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(ecdhPrivateKey)
        keyAgreement.doPhase(mainPublicKey, true)
        val sharedSecret = keyAgreement.generateSecret()
        val aesKwKey = SecretKeySpec(sharedSecret.copyOf(32), "AES")

        // Step 5: AES-KW wrap the main key
        val wrapCipher = Cipher.getInstance("AESWrap")
        wrapCipher.init(Cipher.WRAP_MODE, aesKwKey)
        val wrappedMainKey = wrapCipher.wrap(mainKey)

        return PrfKeyEncapsulation(
            keypair = EncapsulationKeypairInfo(
                publicKey = EncapsulationPublicKeyInfo(
                    importKey = ImportKeyInfo(
                        format = "raw",
                        keyData = publicKeyBytes,
                        algorithm = EcKeyAlgorithm(name = "ECDH", namedCurve = "P-256"),
                    )
                ),
                privateKey = EncapsulationPrivateKeyInfo(
                    unwrapKey = PrivateKeyUnwrapInfo(
                        format = "jwk",
                        wrappedKey = wrappedPrivateKey,
                        unwrapAlgo = AesGcmAlgo(name = "AES-GCM", iv = iv),
                        unwrappedKeyAlgo = EcKeyAlgorithm(name = "ECDH", namedCurve = "P-256"),
                    )
                ),
            ),
            unwrapKey = StaticUnwrapKeyInfo(
                wrappedKey = wrappedMainKey,
                unwrappingKey = UnwrappingKeyInfo(
                    deriveKey = DeriveKeyInfo(
                        algorithm = AlgorithmName("ECDH"),
                        derivedKeyAlgorithm = AesKwAlgorithm(name = "AES-KW", length = 256),
                    )
                ),
            ),
        )
    }

    /**
     * Generate a fresh main key and its ephemeral ECDH public key info.
     */
    fun generateMainKey(): Pair<SecretKey, MainKeyInfo> {
        // Generate random AES-256-GCM main key
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val mainKey = SecretKeySpec(keyBytes, "AES")

        // Generate ephemeral ECDH keypair for the main key (only public key is stored)
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val ecdhKeypair = kpg.generateKeyPair()
        val publicKeyBytes = exportEcPublicKey(ecdhKeypair.public as ECPublicKey)

        val info = MainKeyInfo(
            publicKey = EncapsulationPublicKeyInfo(
                importKey = ImportKeyInfo(
                    format = "raw",
                    keyData = publicKeyBytes,
                    algorithm = EcKeyAlgorithm(name = "ECDH", namedCurve = "P-256"),
                )
            ),
            unwrapKey = MainUnwrapKeyInfo(
                format = "raw",
                unwrapAlgo = "AES-KW",
                unwrappedKeyAlgo = AesGcmKeyAlgorithm(name = "AES-GCM", length = 256),
            ),
        )
        return Pair(mainKey, info)
    }

    // ── EC key helpers ──────────────────────────────────────────────

    private fun unwrapEcdhPrivateKey(
        wrappingKey: SecretKey,
        privateKeyInfo: EncapsulationPrivateKeyInfo,
    ): ECPrivateKey {
        val unwrapInfo = privateKeyInfo.unwrapKey
        // Decrypt the wrapped private key using AES-GCM
        val jwkBytes = aesGcmDecrypt(wrappingKey, unwrapInfo.unwrapAlgo.iv, unwrapInfo.wrappedKey)
        // Parse the JWK and import the EC private key
        val jwkJson = json.parseToJsonElement(String(jwkBytes, Charsets.UTF_8)).jsonObject
        return importEcPrivateKeyJwk(jwkJson)
    }

    private fun importEcPublicKey(rawBytes: ByteArray): ECPublicKey {
        // Uncompressed point format: 0x04 || x || y (65 bytes for P-256)
        val spec = java.security.spec.ECParameterSpec(
            java.security.spec.EllipticCurve(
                java.security.spec.ECFieldFp(
                    java.math.BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
                ),
                java.math.BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
                java.math.BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
            ),
            java.security.spec.ECPoint(
                java.math.BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
                java.math.BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
            ),
            java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
            1,
        )
        val point = java.security.spec.ECPoint(
            java.math.BigInteger(1, rawBytes.copyOfRange(1, 33)),
            java.math.BigInteger(1, rawBytes.copyOfRange(33, 65)),
        )
        val pubKeySpec = java.security.spec.ECPublicKeySpec(point, spec)
        return KeyFactory.getInstance("EC").generatePublic(pubKeySpec) as ECPublicKey
    }

    private fun exportEcPublicKey(key: ECPublicKey): ByteArray {
        val x = key.w.affineX.toByteArray().let { padOrTrim(it, 32) }
        val y = key.w.affineY.toByteArray().let { padOrTrim(it, 32) }
        return byteArrayOf(0x04) + x + y
    }

    private fun padOrTrim(bytes: ByteArray, len: Int): ByteArray {
        return when {
            bytes.size == len -> bytes
            bytes.size > len -> bytes.copyOfRange(bytes.size - len, bytes.size) // trim leading zeros
            else -> ByteArray(len - bytes.size) + bytes // pad with leading zeros
        }
    }

    private fun exportEcPrivateKeyJwk(privateKey: ECPrivateKey, publicKey: ECPublicKey): ByteArray {
        val x = b64Url.encodeToString(padOrTrim(publicKey.w.affineX.toByteArray().let { padOrTrim(it, 32) }, 32))
        val y = b64Url.encodeToString(padOrTrim(publicKey.w.affineY.toByteArray().let { padOrTrim(it, 32) }, 32))
        val d = b64Url.encodeToString(padOrTrim(privateKey.s.toByteArray().let { padOrTrim(it, 32) }, 32))
        val jwk = buildJsonObject {
            put("kty", JsonPrimitive("EC"))
            put("crv", JsonPrimitive("P-256"))
            put("x", JsonPrimitive(x))
            put("y", JsonPrimitive(y))
            put("d", JsonPrimitive(d))
            put("key_ops", kotlinx.serialization.json.JsonArray(listOf(JsonPrimitive("deriveKey"))))
            put("ext", JsonPrimitive(true))
        }
        return json.encodeToString(JsonObject.serializer(), jwk).toByteArray(Charsets.UTF_8)
    }

    private fun importEcPrivateKeyJwk(jwk: JsonObject): ECPrivateKey {
        val d = b64UrlDecoder.decode(jwk["d"]!!.jsonPrimitive.content)
        val x = b64UrlDecoder.decode(jwk["x"]!!.jsonPrimitive.content)
        val y = b64UrlDecoder.decode(jwk["y"]!!.jsonPrimitive.content)

        val spec = java.security.spec.ECParameterSpec(
            java.security.spec.EllipticCurve(
                java.security.spec.ECFieldFp(
                    java.math.BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
                ),
                java.math.BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
                java.math.BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
            ),
            java.security.spec.ECPoint(
                java.math.BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
                java.math.BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
            ),
            java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
            1,
        )
        val privKeySpec = java.security.spec.ECPrivateKeySpec(
            java.math.BigInteger(1, d), spec
        )
        return KeyFactory.getInstance("EC").generatePrivate(privKeySpec) as ECPrivateKey
    }

    // ── AES-GCM helpers ─────────────────────────────────────────────

    private fun aesGcmEncrypt(key: SecretKey, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(key: SecretKey, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }

    // ── HKDF ────────────────────────────────────────────────────────

    internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outputLen: Int): ByteArray {
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        require(outputLen <= 32) { "HKDF output length must be <= 32 for single-block expand" }
        val expandInput = ByteArray(info.size + 1)
        System.arraycopy(info, 0, expandInput, 0, info.size)
        expandInput[info.size] = 0x01
        return hmacSha256(prk, expandInput).copyOf(outputLen)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // ── Container JSON serialization ────────────────────────────────

    private fun parseContainer(obj: JsonObject): ContainerData {
        val jwe = obj["jwe"]!!.jsonPrimitive.content
        val mainKey = obj["mainKey"]?.jsonObject?.let { parseMainKeyInfo(it) }
        val prfKeys = obj["prfKeys"]?.let { element ->
            when (element) {
                is kotlinx.serialization.json.JsonArray -> element.map { parsePrfKeyInfo(it.jsonObject) }
                else -> emptyList()
            }
        } ?: emptyList()

        return ContainerData(
            jwe = jwe,
            mainKey = mainKey,
            prfKeys = prfKeys,
        )
    }

    private fun parseMainKeyInfo(obj: JsonObject): MainKeyInfo {
        val publicKey = obj["publicKey"]!!.jsonObject
        val importKey = publicKey["importKey"]!!.jsonObject
        val unwrapKey = obj["unwrapKey"]!!.jsonObject

        return MainKeyInfo(
            publicKey = EncapsulationPublicKeyInfo(
                importKey = ImportKeyInfo(
                    format = importKey["format"]!!.jsonPrimitive.content,
                    keyData = decodeBinaryField(importKey["keyData"]!!),
                    algorithm = EcKeyAlgorithm(
                        name = importKey["algorithm"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                        namedCurve = importKey["algorithm"]!!.jsonObject["namedCurve"]!!.jsonPrimitive.content,
                    ),
                )
            ),
            unwrapKey = MainUnwrapKeyInfo(
                format = unwrapKey["format"]!!.jsonPrimitive.content,
                unwrapAlgo = unwrapKey["unwrapAlgo"]!!.jsonPrimitive.content,
                unwrappedKeyAlgo = AesGcmKeyAlgorithm(
                    name = unwrapKey["unwrappedKeyAlgo"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                    length = unwrapKey["unwrappedKeyAlgo"]!!.jsonObject["length"]!!.jsonPrimitive.content.toInt(),
                ),
            ),
        )
    }

    private fun parsePrfKeyInfo(obj: JsonObject): PrfKeyInfo {
        val credentialId = decodeBinaryField(obj["credentialId"]!!)
        val prfSalt = decodeBinaryField(obj["prfSalt"]!!)
        val hkdfSalt = decodeBinaryField(obj["hkdfSalt"]!!)
        val hkdfInfo = decodeBinaryField(obj["hkdfInfo"]!!)

        val algorithm = obj["algorithm"]?.jsonObject?.let {
            AesGcmKeyAlgorithm(
                name = it["name"]!!.jsonPrimitive.content,
                length = it["length"]!!.jsonPrimitive.content.toInt(),
            )
        }
        val transports = obj["transports"]?.let { element ->
            when (element) {
                is kotlinx.serialization.json.JsonArray -> element.map { it.jsonPrimitive.content }
                else -> null
            }
        }

        // Parse keypair (ECDH encapsulation keypair)
        val keypairObj = obj["keypair"]!!.jsonObject
        val keypair = parseEncapsulationKeypair(keypairObj)

        // Parse unwrapKey (wrapped main key)
        val unwrapKeyObj = obj["unwrapKey"]!!.jsonObject
        val unwrapKey = parseStaticUnwrapKey(unwrapKeyObj)

        return PrfKeyInfo(
            credentialId = credentialId,
            transports = transports,
            prfSalt = prfSalt,
            hkdfSalt = hkdfSalt,
            hkdfInfo = hkdfInfo,
            algorithm = algorithm,
            keypair = keypair,
            unwrapKey = unwrapKey,
        )
    }

    private fun parseEncapsulationKeypair(obj: JsonObject): EncapsulationKeypairInfo {
        val publicKeyObj = obj["publicKey"]!!.jsonObject["importKey"]!!.jsonObject
        val privateKeyObj = obj["privateKey"]!!.jsonObject["unwrapKey"]!!.jsonObject

        return EncapsulationKeypairInfo(
            publicKey = EncapsulationPublicKeyInfo(
                importKey = ImportKeyInfo(
                    format = publicKeyObj["format"]!!.jsonPrimitive.content,
                    keyData = decodeBinaryField(publicKeyObj["keyData"]!!),
                    algorithm = EcKeyAlgorithm(
                        name = publicKeyObj["algorithm"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                        namedCurve = publicKeyObj["algorithm"]!!.jsonObject["namedCurve"]!!.jsonPrimitive.content,
                    ),
                )
            ),
            privateKey = EncapsulationPrivateKeyInfo(
                unwrapKey = PrivateKeyUnwrapInfo(
                    format = privateKeyObj["format"]!!.jsonPrimitive.content,
                    wrappedKey = decodeBinaryField(privateKeyObj["wrappedKey"]!!),
                    unwrapAlgo = AesGcmAlgo(
                        name = privateKeyObj["unwrapAlgo"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                        iv = decodeBinaryField(privateKeyObj["unwrapAlgo"]!!.jsonObject["iv"]!!),
                    ),
                    unwrappedKeyAlgo = EcKeyAlgorithm(
                        name = privateKeyObj["unwrappedKeyAlgo"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                        namedCurve = privateKeyObj["unwrappedKeyAlgo"]!!.jsonObject["namedCurve"]!!.jsonPrimitive.content,
                    ),
                )
            ),
        )
    }

    private fun parseStaticUnwrapKey(obj: JsonObject): StaticUnwrapKeyInfo {
        val wrappedKey = decodeBinaryField(obj["wrappedKey"]!!)
        val unwrappingKey = obj["unwrappingKey"]!!.jsonObject
        val deriveKey = unwrappingKey["deriveKey"]!!.jsonObject

        return StaticUnwrapKeyInfo(
            wrappedKey = wrappedKey,
            unwrappingKey = UnwrappingKeyInfo(
                deriveKey = DeriveKeyInfo(
                    algorithm = AlgorithmName(
                        name = deriveKey["algorithm"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                    ),
                    derivedKeyAlgorithm = AesKwAlgorithm(
                        name = deriveKey["derivedKeyAlgorithm"]!!.jsonObject["name"]!!.jsonPrimitive.content,
                        length = deriveKey["derivedKeyAlgorithm"]!!.jsonObject["length"]!!.jsonPrimitive.content.toInt(),
                    ),
                )
            ),
        )
    }

    // ── Serialization to JSON ───────────────────────────────────────

    private fun serializeContainer(container: ContainerData): JsonObject {
        return buildJsonObject {
            container.mainKey?.let { put("mainKey", serializeMainKeyInfo(it)) }
            put("prfKeys", kotlinx.serialization.json.JsonArray(
                container.prfKeys.map { serializePrfKeyInfo(it) }
            ))
            put("jwe", JsonPrimitive(container.jwe))
        }
    }

    private fun serializeMainKeyInfo(info: MainKeyInfo): JsonObject {
        return buildJsonObject {
            put("publicKey", buildJsonObject {
                put("importKey", buildJsonObject {
                    put("format", JsonPrimitive(info.publicKey.importKey.format))
                    put("keyData", encodeBinaryField(info.publicKey.importKey.keyData))
                    put("algorithm", buildJsonObject {
                        put("name", JsonPrimitive(info.publicKey.importKey.algorithm.name))
                        put("namedCurve", JsonPrimitive(info.publicKey.importKey.algorithm.namedCurve))
                    })
                })
            })
            put("unwrapKey", buildJsonObject {
                put("format", JsonPrimitive(info.unwrapKey.format))
                put("unwrapAlgo", JsonPrimitive(info.unwrapKey.unwrapAlgo))
                put("unwrappedKeyAlgo", buildJsonObject {
                    put("name", JsonPrimitive(info.unwrapKey.unwrappedKeyAlgo.name))
                    put("length", JsonPrimitive(info.unwrapKey.unwrappedKeyAlgo.length))
                })
            })
        }
    }

    private fun serializePrfKeyInfo(info: PrfKeyInfo): JsonObject {
        return buildJsonObject {
            put("credentialId", encodeBinaryField(info.credentialId))
            info.transports?.let { transports ->
                put("transports", kotlinx.serialization.json.JsonArray(
                    transports.map { JsonPrimitive(it) }
                ))
            }
            put("prfSalt", encodeBinaryField(info.prfSalt))
            put("hkdfSalt", encodeBinaryField(info.hkdfSalt))
            put("hkdfInfo", encodeBinaryField(info.hkdfInfo))
            info.algorithm?.let {
                put("algorithm", buildJsonObject {
                    put("name", JsonPrimitive(it.name))
                    put("length", JsonPrimitive(it.length))
                })
            }
            put("keypair", serializeEncapsulationKeypair(info.keypair))
            put("unwrapKey", serializeStaticUnwrapKey(info.unwrapKey))
        }
    }

    private fun serializeEncapsulationKeypair(info: EncapsulationKeypairInfo): JsonObject {
        return buildJsonObject {
            put("publicKey", buildJsonObject {
                put("importKey", buildJsonObject {
                    put("format", JsonPrimitive(info.publicKey.importKey.format))
                    put("keyData", encodeBinaryField(info.publicKey.importKey.keyData))
                    put("algorithm", buildJsonObject {
                        put("name", JsonPrimitive(info.publicKey.importKey.algorithm.name))
                        put("namedCurve", JsonPrimitive(info.publicKey.importKey.algorithm.namedCurve))
                    })
                })
            })
            put("privateKey", buildJsonObject {
                put("unwrapKey", buildJsonObject {
                    put("format", JsonPrimitive(info.privateKey.unwrapKey.format))
                    put("wrappedKey", encodeBinaryField(info.privateKey.unwrapKey.wrappedKey))
                    put("unwrapAlgo", buildJsonObject {
                        put("name", JsonPrimitive(info.privateKey.unwrapKey.unwrapAlgo.name))
                        put("iv", encodeBinaryField(info.privateKey.unwrapKey.unwrapAlgo.iv))
                    })
                    put("unwrappedKeyAlgo", buildJsonObject {
                        put("name", JsonPrimitive(info.privateKey.unwrapKey.unwrappedKeyAlgo.name))
                        put("namedCurve", JsonPrimitive(info.privateKey.unwrapKey.unwrappedKeyAlgo.namedCurve))
                    })
                })
            })
        }
    }

    private fun serializeStaticUnwrapKey(info: StaticUnwrapKeyInfo): JsonObject {
        return buildJsonObject {
            put("wrappedKey", encodeBinaryField(info.wrappedKey))
            put("unwrappingKey", buildJsonObject {
                put("deriveKey", buildJsonObject {
                    put("algorithm", buildJsonObject {
                        put("name", JsonPrimitive(info.unwrappingKey.deriveKey.algorithm.name))
                    })
                    put("derivedKeyAlgorithm", buildJsonObject {
                        put("name", JsonPrimitive(info.unwrappingKey.deriveKey.derivedKeyAlgorithm.name))
                        put("length", JsonPrimitive(info.unwrappingKey.deriveKey.derivedKeyAlgorithm.length))
                    })
                })
            })
        }
    }

    // ── Tagged binary encoding ──────────────────────────────────────

    private fun decodeBinaryField(element: JsonElement): ByteArray {
        return when (element) {
            is JsonObject -> {
                val b64u = element["\$b64u"]?.jsonPrimitive?.content
                    ?: throw KeystoreException("Expected \$b64u tagged binary")
                b64UrlDecoder.decode(b64u)
            }
            is JsonPrimitive -> b64UrlDecoder.decode(element.content)
            else -> throw KeystoreException("Unexpected JSON element for binary field")
        }
    }

    private fun encodeBinaryField(data: ByteArray): JsonObject {
        return buildJsonObject {
            put("\$b64u", JsonPrimitive(b64Url.encodeToString(data)))
        }
    }
}

// ── Data classes matching the wallet-frontend container format ───────

data class ContainerData(
    val jwe: String,
    val mainKey: MainKeyInfo?,
    val prfKeys: List<PrfKeyInfo>,
)

data class MainKeyInfo(
    val publicKey: EncapsulationPublicKeyInfo,
    val unwrapKey: MainUnwrapKeyInfo,
)

data class MainUnwrapKeyInfo(
    val format: String,
    val unwrapAlgo: String,
    val unwrappedKeyAlgo: AesGcmKeyAlgorithm,
)

data class AesGcmKeyAlgorithm(val name: String, val length: Int)

data class EncapsulationPublicKeyInfo(val importKey: ImportKeyInfo)

data class ImportKeyInfo(
    val format: String,
    val keyData: ByteArray,
    val algorithm: EcKeyAlgorithm,
) {
    override fun equals(other: Any?): Boolean = other is ImportKeyInfo && keyData.contentEquals(other.keyData) && format == other.format
    override fun hashCode(): Int = keyData.contentHashCode()
}

data class EcKeyAlgorithm(val name: String, val namedCurve: String)

data class EncapsulationKeypairInfo(
    val publicKey: EncapsulationPublicKeyInfo,
    val privateKey: EncapsulationPrivateKeyInfo,
)

data class EncapsulationPrivateKeyInfo(val unwrapKey: PrivateKeyUnwrapInfo)

data class PrivateKeyUnwrapInfo(
    val format: String,
    val wrappedKey: ByteArray,
    val unwrapAlgo: AesGcmAlgo,
    val unwrappedKeyAlgo: EcKeyAlgorithm,
) {
    override fun equals(other: Any?): Boolean = other is PrivateKeyUnwrapInfo && wrappedKey.contentEquals(other.wrappedKey)
    override fun hashCode(): Int = wrappedKey.contentHashCode()
}

data class AesGcmAlgo(val name: String, val iv: ByteArray) {
    override fun equals(other: Any?): Boolean = other is AesGcmAlgo && iv.contentEquals(other.iv)
    override fun hashCode(): Int = iv.contentHashCode()
}

data class StaticUnwrapKeyInfo(
    val wrappedKey: ByteArray,
    val unwrappingKey: UnwrappingKeyInfo,
) {
    override fun equals(other: Any?): Boolean = other is StaticUnwrapKeyInfo && wrappedKey.contentEquals(other.wrappedKey)
    override fun hashCode(): Int = wrappedKey.contentHashCode()
}

data class UnwrappingKeyInfo(val deriveKey: DeriveKeyInfo)
data class DeriveKeyInfo(val algorithm: AlgorithmName, val derivedKeyAlgorithm: AesKwAlgorithm)
data class AlgorithmName(val name: String)
data class AesKwAlgorithm(val name: String, val length: Int)

data class PrfKeyInfo(
    val credentialId: ByteArray,
    val transports: List<String>?,
    val prfSalt: ByteArray,
    val hkdfSalt: ByteArray,
    val hkdfInfo: ByteArray,
    val algorithm: AesGcmKeyAlgorithm?,
    val keypair: EncapsulationKeypairInfo,
    val unwrapKey: StaticUnwrapKeyInfo,
) {
    override fun equals(other: Any?): Boolean = other is PrfKeyInfo && credentialId.contentEquals(other.credentialId)
    override fun hashCode(): Int = credentialId.contentHashCode()
}

/** Result of wrapping a main key for a PRF key entry. */
data class PrfKeyEncapsulation(
    val keypair: EncapsulationKeypairInfo,
    val unwrapKey: StaticUnwrapKeyInfo,
)
