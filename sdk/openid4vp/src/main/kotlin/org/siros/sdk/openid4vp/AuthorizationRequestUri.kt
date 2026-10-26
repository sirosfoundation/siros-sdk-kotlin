// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import java.net.URLDecoder

/**
 * An OpenID4VP authorization request passed by reference (OpenID4VP 1.0 section 5.7), as a QR code or a same-device link
 * carries it: `openid4vp://?client_id=…&request_uri=…[&request_uri_method=post]`. The request itself is fetched from
 * [requestUri] and must be signed; a request passed by value (`request` or bare parameters) is refused, since nothing
 * would bind it to the verifier.
 */
class AuthorizationRequestUri private constructor(
    /** The verifier's `client_id`, with its scheme prefix (`x509_san_dns:community.example`). */
    val clientId: String,
    /** Where the signed request object is fetched. */
    val requestUri: String,
    /** `request_uri_method`: POST lets the wallet send its metadata and a `wallet_nonce`. */
    val requestUriMethod: RequestUriMethod,
) {
    enum class RequestUriMethod { GET, POST }

    override fun toString() = "AuthorizationRequestUri($clientId)"

    companion object {
        /** The custom scheme of OpenID4VP 1.0 (section 13.1.2). */
        const val SCHEME = "openid4vp"

        /** @throws OpenId4VpException.InvalidRequestUri when [uri] is not an OpenID4VP request by reference. */
        fun parse(uri: String): AuthorizationRequestUri {
            fun invalid(reason: String): Nothing = throw OpenId4VpException.InvalidRequestUri(reason)
            val text = uri.trim().substringBefore('#')
            val colon = text.indexOf(':')
            if (colon <= 0 || !text.substring(0, colon).equals(SCHEME, ignoreCase = true)) invalid("the scheme is not $SCHEME")
            val q = text.indexOf('?')
            if (q < 0) invalid("no parameters")
            val params = LinkedHashMap<String, String>()
            for (part in text.substring(q + 1).split('&')) {
                if (part.isEmpty()) continue
                val key = decode(part.substringBefore('='))
                val value = decode(part.substringAfter('=', ""))
                if (params.put(key, value) != null) invalid("$key is given twice")
            }
            if ("request" in params || "presentation_definition" in params || "dcql_query" in params) {
                invalid("a request passed by value is not supported: it must be signed and fetched by reference")
            }
            val clientId = params["client_id"]?.takeIf { it.isNotEmpty() } ?: invalid("no client_id")
            val requestUri = params["request_uri"]?.takeIf { it.isNotEmpty() } ?: invalid("no request_uri")
            val method = when (params["request_uri_method"]?.lowercase()) {
                null, "get" -> RequestUriMethod.GET
                "post" -> RequestUriMethod.POST
                else -> invalid("request_uri_method is neither get nor post")
            }
            return AuthorizationRequestUri(clientId, requestUri, method)
        }

        private fun decode(s: String): String = try {
            URLDecoder.decode(s, "UTF-8")
        } catch (e: IllegalArgumentException) {
            throw OpenId4VpException.InvalidRequestUri("a parameter is not URL-encoded")
        }
    }
}
