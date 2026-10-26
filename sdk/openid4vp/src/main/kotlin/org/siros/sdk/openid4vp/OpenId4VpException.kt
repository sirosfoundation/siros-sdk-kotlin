// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

/**
 * Why an OpenID4VP exchange stopped. Messages name the rule, never the request's contents (no nonce, state, token or key).
 */
sealed class OpenId4VpException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** The scanned or linked URI is not an OpenID4VP request this client can fetch. */
    class InvalidRequestUri(val reason: String) : OpenId4VpException("Not an OpenID4VP request URI: $reason")

    /**
     * The request object is not one the wallet may answer: unsigned, not signed by the verifier its `client_id` names, for
     * another wallet session, expired, or from a verifier the [VerifierTrustPolicy] does not trust.
     */
    class Untrusted(val reason: UntrustedReason) : OpenId4VpException("Untrusted request: $reason")

    /** A signed, trusted request that asks for something this client does not do (another response mode, no encryption key...). */
    class Unsupported(val reason: String) : OpenId4VpException("Unsupported request: $reason")

    /**
     * The verifier answered the `request_uri` with an error. [expired] is HTTP 410 (the request was used, cancelled or timed
     * out: the user scans a new code). [code] is the verifier's error code when its body names one.
     */
    class RequestUnavailable(val status: Int, val code: String?) :
        OpenId4VpException("request_uri answered $status${code?.let { " $it" }.orEmpty()}") {
        val expired: Boolean get() = status == 410
    }

    /** The verifier refused the response at `response_uri` (HTTP status, and its error code when it names one). */
    class ResponseRejected(val status: Int, val code: String?) :
        OpenId4VpException("response_uri answered $status${code?.let { " $it" }.orEmpty()}") {
        val expired: Boolean get() = status == 410
    }

    /** The verifier could not be reached, or its answer could not be read. */
    class Network(cause: Throwable) : OpenId4VpException("Network: ${cause.javaClass.simpleName}", cause)
}

/** Why a request object is refused before anything of it is used. */
enum class UntrustedReason {
    /** Not a compact JWS (an unsigned or `alg: none` request). */
    UNSIGNED,

    /** Signed with something other than ES256. */
    UNSUPPORTED_ALGORITHM,

    /** No `x5c` certificate chain in the JWS header. */
    NO_CERTIFICATE,

    /** The leaf certificate does not parse, is outside its validity period, or does not hold a P-256 key. */
    CERTIFICATE_INVALID,

    /** The `client_id` scheme is not `x509_san_dns`, the only one this client verifies. */
    UNSUPPORTED_CLIENT_ID_SCHEME,

    /** The leaf certificate has no dNSName SAN equal to the `client_id` host. */
    SAN_MISMATCH,

    /** The signature does not verify under the leaf certificate's key. */
    SIGNATURE_INVALID,

    /** The payload is not a JSON object. */
    MALFORMED,

    /** The payload's `client_id` is not the one the request URI named. */
    CLIENT_ID_MISMATCH,

    /** The payload's `wallet_nonce` is not the one this wallet posted (a replayed or substituted request). */
    WALLET_NONCE_MISMATCH,

    /** The payload's `exp` has passed. */
    EXPIRED,

    /** Signed by the verifier it names, but the [VerifierTrustPolicy] does not trust that verifier. */
    NOT_TRUSTED,
}
