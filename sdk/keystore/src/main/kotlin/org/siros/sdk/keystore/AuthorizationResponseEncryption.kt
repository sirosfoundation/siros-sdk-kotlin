// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * Builds the OpenID4VP `direct_post.jwt` response (JARM, OpenID4VP 1.0 section 8.3) on the wallet: the `vp_token`
 * encrypted to the verifier's key, so whoever POSTs it (the engine, for `SirosWallet`; or a direct OpenID4VP client)
 * never holds the `vp_token`. [isConformant] is the engine's acceptance rule for `response_jwe`
 * (go-wallet-backend#471); [encrypt] never returns a response that breaks it.
 *
 * Nothing here logs. (Moved from `sdk:wallet`, where it was internal, so a client below the wallet engine can use it.)
 */
object AuthorizationResponseEncryption {
    private const val JARM_ISSUER = "https://self-issued.me/v2"
    private const val JARM_LIFETIME_SECONDS = 300L

    /**
     * The RFC 7638 thumbprint (base64url, unpadded, SHA-256) of the verifier's public key. For `direct_post.jwt` this is the ONE source
     * of the mdoc session transcript's thumbprint: the key the response is encrypted to.
     *
     * @throws IllegalArgumentException when [jwk] is not a usable public JWK.
     */
    fun jwkThumbprint(jwk: JsonObject): String {
        val parsed = try {
            JWK.parse(jwk.toString())
        } catch (e: Exception) {
            throw IllegalArgumentException("The verifier's encryption key is not a JWK")
        }
        require(!parsed.isPrivate) { "The verifier's encryption key must be a public key" }
        return try {
            parsed.computeThumbprint().toString()
        } catch (e: Exception) {
            throw IllegalArgumentException("The verifier's encryption key has no thumbprint")
        }
    }

    /** The engine refuses a larger `response_jwe`. */
    const val MAX_RESPONSE_JWE_BYTES = 4 * 1024 * 1024

    /**
     * Whether [jwe] is a compact JWE the engine accepts: five base64url segments, none empty (the encrypted-key segment
     * may be empty only for direct `ECDH-ES`), at most [MAX_RESPONSE_JWE_BYTES], whose protected header carries exactly
     * [alg], [enc] and, when the verifier's JWK has one, its [kid] (and none when it has not).
     */
    fun isConformant(jwe: String, alg: String, enc: String, kid: String?): Boolean {
        if (jwe.isEmpty() || jwe.length > MAX_RESPONSE_JWE_BYTES) return false
        val segments = jwe.split('.')
        if (segments.size != 5) return false
        val b64 = Regex("^[A-Za-z0-9_-]*$")
        if (segments.any { !b64.matches(it) }) return false
        if (segments.withIndex().any { (i, s) -> s.isEmpty() && !(i == 1 && alg == "ECDH-ES") }) return false
        val header = try {
            JWEHeader.parse(com.nimbusds.jose.util.Base64URL(segments[0]))
        } catch (e: Exception) {
            return false
        }
        return header.algorithm.name == alg && header.encryptionMethod.name == enc && header.keyID == kid
    }

    /**
     * The compact JWE of the response: claims `iss`, `aud`, `iat`, `exp` (`iat` + 300 s), `vp_token` and, when the
     * request had one, `state`; protected header `alg`, `enc` and the verifier key's `kid` (no `cty`: the plaintext is plain JSON
     * claims, not a nested JWT, which RFC 7519 section 5.2 says not to mark and a strict verifier would try to parse as one).
     *
     * @param vpToken the DCQL `{queryId: [tokens]}` object, or the bare token string for a request without DCQL.
     * @param verifierJwk the verifier's public key exactly as the engine resolved it (EC or RSA, with its `kid`).
     * @throws IllegalArgumentException when [verifierJwk] is not a usable public EC or RSA key, or [alg]/[enc] is
     *   not one this wallet can apply to it.
     */
    fun encrypt(
        vpToken: JsonElement,
        audience: String,
        state: String?,
        verifierJwk: JsonObject,
        alg: String,
        enc: String,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
    ): String {
        val claims = buildJsonObject {
            put("iss", JsonPrimitive(JARM_ISSUER))
            put("aud", JsonPrimitive(audience))
            put("iat", JsonPrimitive(nowSeconds))
            put("exp", JsonPrimitive(nowSeconds + JARM_LIFETIME_SECONDS))
            put("vp_token", vpToken)
            if (!state.isNullOrEmpty()) put("state", JsonPrimitive(state))
        }
        val jwk = try {
            JWK.parse(verifierJwk.toString())
        } catch (e: Exception) {
            throw IllegalArgumentException("The verifier's encryption key is not a JWK")
        }
        require(!jwk.isPrivate) { "The verifier's encryption key must be a public key" }
        val header = JWEHeader.Builder(JWEAlgorithm.parse(alg), EncryptionMethod.parse(enc))
            .apply { jwk.keyID?.let { keyID(it) } }
            .build()
        val encrypter = when (jwk) {
            is ECKey -> ECDHEncrypter(jwk)
            is RSAKey -> RSAEncrypter(jwk)
            else -> throw IllegalArgumentException("Unsupported verifier key type ${jwk.keyType}")
        }
        val obj = JWEObject(header, Payload(claims.toString()))
        try {
            obj.encrypt(encrypter)
        } catch (e: Exception) {
            throw IllegalArgumentException("The response could not be encrypted to the verifier's key with $alg/$enc")
        }
        val serialized = obj.serialize()
        // The engine refuses anything else, so a response it would refuse is never sent.
        require(isConformant(serialized, alg, enc, jwk.keyID)) { "The encrypted response is not a conformant compact JWE (too large or malformed)" }
        return serialized
    }
}
