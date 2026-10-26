// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * The wallet's half of "the engine never sees credential contents": the keys and the JWE work that used to run
 * inside the engine, so the engine relays ciphertext only (see the engine-blind encryption contract). The presentation
 * side, [org.siros.sdk.keystore.AuthorizationResponseEncryption], is in `sdk:keystore`.
 *
 * Nothing here logs, and no object here prints a key or a plaintext.
 */

/**
 * A fresh ephemeral P-256 key for ONE OpenID4VCI credential request's response encryption (OpenID4VCI 1.0 section 8.3.1).
 * The engine sends the issuer only [publicJwk]; the issuer's JWE can be opened here and nowhere else.
 *
 * Held in memory only, for the life of one flow, and never serialised: there is deliberately no way to export the
 * private half. [alg] and [enc] are the pair the engine negotiated against the issuer's metadata, and the issuer's JWE
 * must use exactly that pair ([decrypt] refuses anything else).
 */
internal class CredentialResponseKey private constructor(
    private val key: ECKey,
    val alg: String,
    val enc: String,
) {
    /** The public JWK to put in `credential_response_encryption.jwk`: `{kty, crv, x, y, use: "enc", alg}`. */
    val publicJwk: JsonObject = Json.parseToJsonElement(key.toPublicJWK().toJSONString()) as JsonObject

    /**
     * Opens a compact JWE the issuer returned and returns its plaintext (the Credential Response JSON).
     *
     * @throws IllegalArgumentException when [jwe] is not a compact JWE, uses an algorithm other than the negotiated
     *   pair, or does not decrypt under this key. The message never carries the JWE or any plaintext.
     */
    fun decrypt(jwe: String): String {
        val obj = try {
            JWEObject.parse(jwe)
        } catch (e: Exception) {
            throw IllegalArgumentException("The credential response is not a compact JWE")
        }
        val header = obj.header
        require(header.algorithm.name == alg && header.encryptionMethod.name == enc) {
            "The credential response uses ${header.algorithm.name}/${header.encryptionMethod.name}, not the negotiated $alg/$enc"
        }
        try {
            obj.decrypt(ECDHDecrypter(key))
        } catch (e: Exception) {
            throw IllegalArgumentException("The credential response could not be decrypted")
        }
        return obj.payload.toString()
    }

    override fun toString() = "CredentialResponseKey($alg/$enc, <redacted>)"

    companion object {
        /** The key-agreement algorithms the engine may negotiate: ECDH-ES direct, or with an AES key wrap. */
        val SUPPORTED_ALGS = setOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")

        /** The content encryption methods the engine may negotiate. */
        val SUPPORTED_ENCS = setOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")

        /**
         * @return a fresh key for the negotiated pair, or null when the wallet cannot decrypt that pair (the caller
         *   then declines, which the engine treats as a refusal when the issuer REQUIRES encryption).
         */
        fun generate(alg: String, enc: String): CredentialResponseKey? {
            if (alg !in SUPPORTED_ALGS || enc !in SUPPORTED_ENCS) return null
            val key = ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.parse(alg))
                .generate()
            return CredentialResponseKey(key, alg, enc)
        }
    }
}
