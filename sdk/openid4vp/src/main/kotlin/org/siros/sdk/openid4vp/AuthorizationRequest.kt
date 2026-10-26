// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import java.net.URI
import java.security.cert.X509Certificate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.keystore.AuthorizationResponseEncryption
import org.siros.sdk.keystore.MdocDeviceResponseBuilder

/**
 * A signed OpenID4VP request this client can answer, checked: the request object verified ([RequestObjectVerifier]), the
 * verifier trusted ([VerifierTrustPolicy]), and the request shaped as this client supports it:
 *
 * - `response_type` `vp_token`, `response_mode` `direct_post.jwt` (the response is always encrypted), an https
 *   `response_uri`, a `nonce`;
 * - a DCQL query (`presentation_definition` is not supported), no `transaction_data`;
 * - a response-encryption key in `client_metadata.jwks`: the first whose `use` is `enc` or absent, `alg` `ECDH-ES`, on
 *   P-256; `enc` A128GCM unless `encrypted_response_enc_values_supported` lists only A256GCM.
 */
class AuthorizationRequest internal constructor(
    /** The verifier's `client_id` (`x509_san_dns:<host>`): the JARM `aud`, and the `verifier_id` of a pseudonym. */
    val clientId: String,
    /** Where the request object was fetched. */
    val requestUri: String,
    /** Where the response is posted. */
    val responseUri: String,
    val nonce: String,
    /** Echoed in the response; null when the request had none. */
    val state: String?,
    val dcqlQuery: JsonObject,
    val clientMetadata: JsonObject,
    /** The verifier's public response-encryption key, as `client_metadata.jwks` gave it. */
    val responseEncryptionJwk: JsonObject,
    /** Always `ECDH-ES`. */
    val responseEncryptionAlg: String,
    /** `A128GCM` or `A256GCM`. */
    val responseEncryptionEnc: String,
    /** The RFC 7638 thumbprint of [responseEncryptionJwk]: the handover binds the proof to the key the response goes to. */
    val responseEncryptionJwkThumbprint: String,
    /** The `x5c` chain the request was signed with, leaf first. */
    val certificateChain: List<X509Certificate>,
    /** The whole verified request object. */
    val payload: JsonObject,
) {
    /** The `client_id` host: the name the user is shown, and the leaf certificate's dNSName. */
    val verifierHost: String get() = clientId.substringAfter(':')

    /** `client_metadata.client_name`, when the verifier gave one. Unverified: show it next to [verifierHost], never instead. */
    val clientName: String? get() = (clientMetadata["client_name"] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /**
     * The session transcript a presentation to this request is bound to: the `OpenID4VPHandover` of OpenID4VP 1.0 B.2.6.1
     * over `[client_id, nonce, JWK thumbprint, response_uri]` (the redirect handover community-demo and the SDK's
     * `circuit_zk` path use).
     */
    fun sessionTranscript(): ByteArray = MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript(
        clientId = clientId,
        nonce = nonce,
        responseUri = responseUri,
        verifierJwkThumbprint = responseEncryptionJwkThumbprint,
    )

    /** The DCQL credential queries (`dcql_query.credentials`), in the request's order. */
    val credentialQueries: List<JsonObject>
        get() = (dcqlQuery["credentials"] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }

    /** The `zkp_req` credential queries, in the request's order (its order of preference). */
    val circuitZkQueries: List<JsonObject>
        get() = credentialQueries.filter { (it["format"] as? JsonPrimitive)?.content == ZKP_REQ_FORMAT }

    override fun toString() = "AuthorizationRequest($clientId)"

    internal companion object {
        const val ZKP_REQ_FORMAT = "zkp_req"
        private const val RESPONSE_ALG = "ECDH-ES"
        private val RESPONSE_ENCS = listOf("A128GCM", "A256GCM")

        fun from(verified: VerifiedRequestObject, clientId: String, requestUri: String, allowHttp: Boolean): AuthorizationRequest {
            val p = verified.payload
            fun unsupported(reason: String): Nothing = throw OpenId4VpException.Unsupported(reason)
            fun text(name: String) = (p[name] as? JsonPrimitive)?.takeIf { it.isString }?.content

            if (text("response_type") != "vp_token") unsupported("response_type is not vp_token")
            if (text("response_mode") != "direct_post.jwt") unsupported("response_mode is not direct_post.jwt")
            val responseUri = text("response_uri")?.takeIf { isWebUrl(it, allowHttp) } ?: unsupported("response_uri is not an https URL")
            val nonce = text("nonce")?.takeIf { it.isNotEmpty() } ?: unsupported("no nonce")
            val state = p["state"]?.let { (it as? JsonPrimitive)?.takeIf { s -> s.isString }?.content ?: unsupported("state is not a string") }
            if ("presentation_definition" in p) unsupported("presentation_definition is not supported; use dcql_query")
            if ("transaction_data" in p) unsupported("transaction_data is not supported")
            val dcql = p["dcql_query"] as? JsonObject ?: unsupported("no dcql_query")
            if ((dcql["credentials"] as? JsonArray).isNullOrEmpty()) unsupported("dcql_query has no credential query")
            val metadata = p["client_metadata"] as? JsonObject ?: unsupported("no client_metadata")
            val jwk = encryptionKey(metadata) ?: unsupported("client_metadata.jwks has no ECDH-ES P-256 key to encrypt the response to")
            val enc = responseEnc(metadata) ?: unsupported("encrypted_response_enc_values_supported lists neither A128GCM nor A256GCM")
            // Also checks the key is a usable public key (a point on P-256), before anything is proved for it.
            val thumbprint = try {
                AuthorizationResponseEncryption.jwkThumbprint(jwk)
            } catch (e: IllegalArgumentException) {
                unsupported("the response-encryption key is not a usable public key")
            }
            return AuthorizationRequest(
                clientId = clientId,
                requestUri = requestUri,
                responseUri = responseUri,
                nonce = nonce,
                state = state,
                dcqlQuery = dcql,
                clientMetadata = metadata,
                responseEncryptionJwk = jwk,
                responseEncryptionAlg = RESPONSE_ALG,
                responseEncryptionEnc = enc,
                responseEncryptionJwkThumbprint = thumbprint,
                certificateChain = verified.certificateChain,
                payload = p,
            )
        }

        /** The first key whose `use` is `enc` or absent and whose `alg` is ECDH-ES on P-256, public (no `d`). */
        private fun encryptionKey(metadata: JsonObject): JsonObject? {
            val keys = ((metadata["jwks"] as? JsonObject)?.get("keys") as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
            return keys.firstOrNull { k ->
                fun s(n: String) = (k[n] as? JsonPrimitive)?.takeIf { it.isString }?.content
                (s("use") == null || s("use") == "enc") && s("alg") == RESPONSE_ALG && s("kty") == "EC" && s("crv") == "P-256" &&
                    s("x") != null && s("y") != null && "d" !in k
            }
        }

        /** A128GCM unless the verifier lists values without it; then A256GCM if listed. */
        private fun responseEnc(metadata: JsonObject): String? {
            val listed = metadata["encrypted_response_enc_values_supported"] ?: return RESPONSE_ENCS.first()
            val values = (listed as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            return RESPONSE_ENCS.firstOrNull { it in values }
        }

        fun isWebUrl(url: String, allowHttp: Boolean): Boolean = try {
            val u = URI(url)
            val scheme = u.scheme?.lowercase()
            u.isAbsolute && !u.host.isNullOrEmpty() && u.rawUserInfo == null && (scheme == "https" || (allowHttp && scheme == "http"))
        } catch (e: Exception) {
            false
        }
    }
}
