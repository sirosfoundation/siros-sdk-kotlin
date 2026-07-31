// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK

/**
 * Encrypts an OpenID4VP response for the `dc_api.jwt` response mode
 * (OpenID4VP 1.0 Appendix A.3.2, "Response Encryption").
 *
 * The W3C Digital Credentials API has no TLS-secured `direct_post` channel
 * for the wallet's response (it's returned via the browser's synchronous
 * `navigator.credentials.get()` callback instead of an HTTP POST), so
 * `dc_api.jwt` always requires the response to be JWE-encrypted to a key the
 * verifier published in its request's `client_metadata.jwks` - unlike the
 * redirect flow, where `direct_post.jwt` encryption is an OPTIONAL hardening
 * on top of an already-TLS-secured POST.
 *
 * Mirrors wallet-frontend's `DCAPISession#encryptResponse` (`jose`'s
 * `EncryptJWT`): ECDH-ES key agreement against the verifier's EC public key,
 * A128GCM content encryption by default - both overridable if the verifier's
 * request specifies different `alg`/`enc` values via
 * `authorization_encrypted_response_alg`/`_enc` (or equivalent) metadata.
 */
object DCAPIResponseEncryption {
    /**
     * @param responseJson the full response payload to encrypt, e.g. `{"vp_token": {...}}`.
     * @param verifierJwk the verifier's response-encryption public key (from
     *   `client_metadata.jwks`, the entry with `use: "enc"`) - MUST be an EC key.
     * @return the compact-serialized JWE string.
     */
    fun encryptResponse(
        responseJson: String,
        verifierJwk: JWK,
        alg: JWEAlgorithm = JWEAlgorithm.ECDH_ES,
        enc: EncryptionMethod = EncryptionMethod.A128GCM,
    ): String {
        require(verifierJwk is ECKey) {
            "DC API response encryption requires an EC verifier key, got ${verifierJwk.keyType}"
        }
        // The verifier looks up which of its (possibly many concurrent)
        // ephemeral decryption keys to use by the JWE header's kid - it
        // generates that key specifically with one (see
        // EphemeralEncryptionKeyCache.GenerateAndStore in sirosfoundation/vc)
        // and expects it echoed back here. Omitting this was a real bug:
        // decryption failed with "kid not found in JWT header" before the
        // verifier could even attempt decryption.
        val headerBuilder = JWEHeader.Builder(alg, enc)
        verifierJwk.keyID?.let { headerBuilder.keyID(it) }
        val header = headerBuilder.build()
        val jweObject = JWEObject(header, Payload(responseJson))
        jweObject.encrypt(ECDHEncrypter(verifierJwk))
        return jweObject.serialize()
    }
}
