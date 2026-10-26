// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.util.X509CertChainUtils
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Date
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** A request object whose signature and `client_id` binding checked out. */
internal class VerifiedRequestObject(val payload: JsonObject, val certificateChain: List<X509Certificate>)

/**
 * Checks a signed request object (OpenID4VP 1.0 section 5, client identifier prefix `x509_san_dns`, section 5.9.3) before
 * anything of it is used:
 *
 * 1. a compact JWS, ES256;
 * 2. an `x5c` chain whose leaf is inside its validity period and holds a P-256 key;
 * 3. the leaf has a dNSName SAN equal to the `client_id` host;
 * 4. the signature verifies under the leaf's key;
 * 5. the payload's `client_id` is the one the request URI named, its `wallet_nonce` the one this wallet posted (when it
 *    posted one), and its `exp`, when present, has not passed.
 *
 * The chain is NOT validated against a trust anchor here: that, and whether this verifier may be answered at all, is the
 * [VerifierTrustPolicy]'s decision, made after these checks.
 */
internal object RequestObjectVerifier {
    /** Clock skew allowed on `exp`. */
    private const val SKEW_SECONDS = 60L
    private const val CLIENT_ID_PREFIX = "x509_san_dns:"
    private const val SAN_DNS_NAME = 2

    fun verify(jws: String, clientId: String, walletNonce: String?, now: Instant): VerifiedRequestObject {
        fun untrusted(reason: UntrustedReason): Nothing = throw OpenId4VpException.Untrusted(reason)
        val obj = try {
            JWSObject.parse(jws.trim())
        } catch (e: Exception) {
            untrusted(UntrustedReason.UNSIGNED)
        }
        if (obj.header.algorithm != JWSAlgorithm.ES256) untrusted(UntrustedReason.UNSUPPORTED_ALGORITHM)
        val encoded = obj.header.x509CertChain?.takeIf { it.isNotEmpty() } ?: untrusted(UntrustedReason.NO_CERTIFICATE)
        val chain = try {
            X509CertChainUtils.parse(encoded)
        } catch (e: Exception) {
            untrusted(UntrustedReason.CERTIFICATE_INVALID)
        }
        val leaf = chain.firstOrNull() ?: untrusted(UntrustedReason.NO_CERTIFICATE)
        try {
            leaf.checkValidity(Date.from(now))
        } catch (e: Exception) {
            untrusted(UntrustedReason.CERTIFICATE_INVALID)
        }
        val key = leaf.publicKey as? ECPublicKey ?: untrusted(UntrustedReason.CERTIFICATE_INVALID)
        if (Curve.forECParameterSpec(key.params) != Curve.P_256) untrusted(UntrustedReason.CERTIFICATE_INVALID)

        if (!clientId.startsWith(CLIENT_ID_PREFIX)) untrusted(UntrustedReason.UNSUPPORTED_CLIENT_ID_SCHEME)
        val host = clientId.removePrefix(CLIENT_ID_PREFIX)
        if (host.isEmpty()) untrusted(UntrustedReason.UNSUPPORTED_CLIENT_ID_SCHEME)
        val dnsNames = try {
            leaf.subjectAlternativeNames.orEmpty().filter { it.size >= 2 && it[0] == SAN_DNS_NAME }.mapNotNull { it[1] as? String }
        } catch (e: Exception) {
            untrusted(UntrustedReason.CERTIFICATE_INVALID)
        }
        if (dnsNames.none { it.equals(host, ignoreCase = true) }) untrusted(UntrustedReason.SAN_MISMATCH)

        val verified = try {
            obj.verify(ECDSAVerifier(key))
        } catch (e: Exception) {
            false
        }
        if (!verified) untrusted(UntrustedReason.SIGNATURE_INVALID)

        val payload = try {
            Json.parseToJsonElement(obj.payload.toString()) as? JsonObject
        } catch (e: Exception) {
            null
        } ?: untrusted(UntrustedReason.MALFORMED)
        fun text(name: String) = (payload[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (text("client_id") != clientId) untrusted(UntrustedReason.CLIENT_ID_MISMATCH)
        if (walletNonce != null && text("wallet_nonce") != walletNonce) untrusted(UntrustedReason.WALLET_NONCE_MISMATCH)
        payload["exp"]?.let { exp ->
            val seconds = (exp as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: untrusted(UntrustedReason.MALFORMED)
            if (seconds + SKEW_SECONDS < now.epochSecond) untrusted(UntrustedReason.EXPIRED)
        }
        return VerifiedRequestObject(payload, chain)
    }
}
